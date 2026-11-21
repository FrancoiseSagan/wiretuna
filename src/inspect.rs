use std::{
    collections::BTreeSet,
    error::Error,
    fs::File,
    io::{BufReader, Write},
    path::Path,
};

use wiretuna::{
    capture::{PacketSource, SourceEvent, offline::OfflineReader},
    packet::Timestamp,
};

pub fn run(path: &Path, packets: bool, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let input =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut source = OfflineReader::new(BufReader::new(input))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let header = source.classic_header();

    if packets {
        write!(
            output,
            "packet\ttimestamp_utc_unix\tcaptured_len\toriginal_len\ttruncated"
        )?;
        if header.is_none() {
            write!(output, "\tinterface\tlink_type")?;
        }
        writeln!(output)?;
    }
    let (mut count, mut captured, mut original, mut truncated) = (0u64, 0u128, 0u128, 0u64);
    let mut link_types = BTreeSet::new();
    while let SourceEvent::Packet(packet) = source
        .next_packet()
        .map_err(|error| format!("{}: {error}", path.display()))?
    {
        count += 1;
        captured += u128::from(packet.captured_len());
        original += u128::from(packet.original_len());
        truncated += u64::from(packet.is_truncated());
        if header.is_none() {
            link_types.insert(packet.link_type().0);
        }

        if packets {
            write!(output, "{count}\t")?;
            write_time(output, packet.timestamp())?;
            write!(
                output,
                "\t{}\t{}\t{}",
                packet.captured_len(),
                packet.original_len(),
                packet.is_truncated(),
            )?;
            if header.is_none() {
                write!(
                    output,
                    "\t{}\t{}",
                    packet.interface_id(),
                    packet.link_type().0
                )?;
            }
            writeln!(output)?;
        }
    }
    if let Some(header) = header {
        writeln!(output, "link_type: {}", header.link_type.0)?;
        writeln!(output, "snaplen: {}", header.snaplen)?;
    } else {
        writeln!(output, "format: pcapng")?;
        writeln!(output, "interfaces: {}", source.interface_count())?;
        let types: Vec<_> = link_types
            .into_iter()
            .map(|link| link.to_string())
            .collect();
        writeln!(output, "link_types: {}", types.join(", "))?;
    }
    writeln!(output, "packets: {count}")?;
    writeln!(output, "captured_bytes: {captured}")?;
    writeln!(output, "original_bytes: {original}")?;
    writeln!(output, "truncated_packets: {truncated}")?;
    output.flush()?;
    Ok(())
}

fn write_time(output: &mut impl Write, timestamp: Option<Timestamp>) -> std::io::Result<()> {
    let Some(timestamp) = timestamp else {
        return write!(output, "-");
    };
    let seconds = timestamp.seconds();
    let fraction = timestamp.nanoseconds();
    if seconds < 0 && fraction > 0 {
        write!(
            output,
            "-{}.{:09}",
            seconds.unsigned_abs() - 1,
            1_000_000_000 - fraction
        )
    } else {
        write!(output, "{seconds}.{fraction:09}")
    }
}
