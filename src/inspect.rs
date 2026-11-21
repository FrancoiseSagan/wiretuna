use std::{
    error::Error,
    fs::File,
    io::{BufReader, Write},
    path::Path,
};

use wiretuna::capture::{PacketSource, SourceEvent, pcap::PcapReader};

pub fn run(path: &Path, packets: bool, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let input =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut source = PcapReader::new(BufReader::new(input))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let header = source.header();

    if packets {
        writeln!(
            output,
            "packet\ttimestamp_utc_unix\tcaptured_len\toriginal_len\ttruncated"
        )?;
    }
    let (mut count, mut captured, mut original, mut truncated) = (0u64, 0u128, 0u128, 0u64);
    while let SourceEvent::Packet(packet) = source
        .next_packet()
        .map_err(|error| format!("{}: {error}", path.display()))?
    {
        count += 1;
        captured += u128::from(packet.captured_len());
        original += u128::from(packet.original_len());
        truncated += u64::from(packet.is_truncated());

        if packets {
            // Classic pcap always includes a timestamp.
            let timestamp = packet.timestamp().expect("pcap reader provides timestamps");
            writeln!(
                output,
                "{count}\t{}.{:09}\t{}\t{}\t{}",
                timestamp.seconds(),
                timestamp.nanoseconds(),
                packet.captured_len(),
                packet.original_len(),
                packet.is_truncated(),
            )?;
        }
    }
    writeln!(output, "link_type: {}", header.link_type.0)?;
    writeln!(output, "snaplen: {}", header.snaplen)?;
    writeln!(output, "packets: {count}")?;
    writeln!(output, "captured_bytes: {captured}")?;
    writeln!(output, "original_bytes: {original}")?;
    writeln!(output, "truncated_packets: {truncated}")?;
    output.flush()?;
    Ok(())
}
