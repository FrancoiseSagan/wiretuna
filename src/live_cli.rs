use std::{
    ffi::OsString,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use wiretuna::capture::{
    PacketSource, SourceEvent,
    live::{Config, LiveCapture, interfaces},
};

pub const HELP: &str = "\
Live capture (Linux):
  wiretuna interfaces
  wiretuna capture --interface IFACE [--filter BPF] [--snaplen BYTES]
                   [--buffer-size BYTES] [--count PACKETS]

Capture stops on Ctrl-C or after receiving --count packets.";

pub fn list() -> io::Result<()> {
    for interface in interfaces()? {
        if let Some(description) = interface.description {
            println!("{}\t{description}", interface.name);
        } else {
            println!("{}", interface.name);
        }
    }
    Ok(())
}

pub fn capture(args: &[OsString]) -> io::Result<()> {
    let mut config = Config::default();
    let mut interface = None;
    let mut limit: Option<u64> = None;
    let mut pairs = args.chunks_exact(2);
    for pair in &mut pairs {
        let [flag, value] = pair else {
            unreachable!("pairs have two elements")
        };
        let value = value
            .to_str()
            .ok_or_else(|| invalid("capture options require UTF-8 values"))?;
        match flag.to_str() {
            Some("--interface") => interface = Some(value),
            Some("--filter") => config.filter = Some(value.to_owned()),
            Some("--snaplen") => config.snaplen = parse_positive(value, "--snaplen")?,
            Some("--buffer-size") => config.buffer_size = parse_positive(value, "--buffer-size")?,
            Some("--count") => limit = Some(parse_positive(value, "--count")?),
            _ => return Err(invalid(format!("unknown capture option {flag:?}"))),
        }
    }
    if !pairs.remainder().is_empty() {
        return Err(invalid("capture options require a value"));
    }
    let interface = interface.ok_or_else(|| invalid("capture requires --interface IFACE"))?;
    let stopped = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stopped);
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed)).map_err(io::Error::other)?;

    let mut capture = LiveCapture::open(interface, &config)?;
    eprintln!(
        "capturing on {interface} (link type {})",
        capture.link_type().0
    );
    let mut count = 0u64;
    let mut bytes = 0u128;
    while !stopped.load(Ordering::Relaxed) && limit.is_none_or(|limit| count < limit) {
        match capture.next_packet()? {
            SourceEvent::Packet(packet) => {
                count += 1;
                bytes += u128::from(packet.captured_len());
            }
            SourceEvent::Idle => thread::sleep(Duration::from_millis(10)),
            SourceEvent::End => break,
        }
    }

    println!("packets: {count}\ncaptured_bytes: {bytes}");
    match capture.stats() {
        Ok(stats) => println!(
            "pcap_received: {}\npcap_dropped: {}\npcap_interface_dropped: {}",
            stats.received, stats.dropped, stats.interface_dropped
        ),
        Err(error) => eprintln!("wiretuna: {error}"),
    }
    Ok(())
}

fn parse_positive<T: std::str::FromStr + Default + PartialOrd>(
    value: &str,
    flag: &str,
) -> io::Result<T> {
    value
        .parse::<T>()
        .ok()
        .filter(|value| *value > T::default())
        .ok_or_else(|| invalid(format!("{flag} requires a positive integer")))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
