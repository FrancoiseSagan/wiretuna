# Wiretuna

Wiretuna is a lightweight network packet analyzer written in Rust. The CLI inspects
classic pcap 2.4 files and can capture packets on a single Linux interface.
The offline build runs without libpcap.

```sh
cargo run --locked -- inspect capture.pcap
cargo run --locked -- inspect --packets capture.pcap
```

The reader handles both byte orders and microsecond or nanosecond timestamps.
Per-packet output shows UTC Unix timestamps in seconds with nine fractional
digits. The file is processed as a stream with a 1 MiB limit per stored packet.

## Live capture on Linux

Install the libpcap development package for your distribution (for example,
`libpcap-dev` on Debian or Ubuntu). The capture process needs permission to open
the chosen interface. Select an interface you are authorized to monitor.

```sh
cargo run --locked --features live-capture -- interfaces
cargo run --locked --features live-capture -- capture --interface lo --filter 'udp port 39001'
```

Stop with Ctrl-C or set a packet limit with `--count`. The command reports
captured packets and byte counts along with the raw libpcap counters. The
optional `--snaplen` and `--buffer-size` values are in bytes. Promiscuous mode
is disabled.

## Local Web interface

Build the Web feature and start Wiretuna with an existing capture file:

```sh
cargo run --locked --features web -- serve --input capture.pcap
```

Open `http://127.0.0.1:8765` in a browser. Use `--port` to change the loopback
port. The packet workspace supports display filters such as
`tcp && ip.src == 192.0.2.1`, field inspection and a paginated hex view.
The interface is embedded in the binary and does not need a frontend build.

In the TCP workspace, select a connection to inspect reassembled bytes in
either direction or open its cleartext HTTP/1.1 transactions. Packet detail
links to the connection. Stream segments and HTTP messages link back to their
source packet while it remains in the retention window. Gaps and conflicting
overlaps are reported in the stream, and incomplete HTTP bodies are labeled.
The message view starts with a short body preview and lets you expand the
retained body. It follows the HTTP charset when present and lets you choose
another charset. The browser decompresses
supported content encodings up to 1 MiB of output.

### Release build with live capture

On Linux, build both programs with
`cargo build --release --locked --features web,live-capture`. Keep
`wiretuna` and `wiretuna-capture` next to each other when installing them.
Live capture needs permission to open a packet socket. When using file
capabilities, install the helper in a directory writable only by
administrators and grant `cap_net_raw=ep` to the helper with `setcap`.
Run `wiretuna serve` as an ordinary user. The Web server listens only on
IPv4 loopback. Ctrl-C or SIGTERM stops the active capture and shuts down
the service.

The Web view retains a bounded packet window and bounded TCP stream data.
The `inspect` command traverses the entire classic pcap file. HTTP analysis
covers plaintext HTTP/1.1. Encrypted traffic remains available in the packet
and TCP views as captured bytes.

The Linux CI runs the Rust tests with and without live capture and runs the
offline Web smoke test against the built executable.
