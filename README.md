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
