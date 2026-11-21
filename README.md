# Wiretuna

Wiretuna is a lightweight network packet analyzer written in Rust. The current
CLI inspects classic pcap 2.4 files and reports packet counts, capture lengths,
and truncation. It uses only the Rust standard library.

```sh
cargo run --locked -- inspect capture.pcap
cargo run --locked -- inspect --packets capture.pcap
```

The reader handles both byte orders and microsecond or nanosecond timestamps.
Per-packet output shows UTC Unix timestamps in seconds with nine fractional
digits. The file is processed as a stream with a 1 MiB limit per stored packet.
