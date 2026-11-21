use wiretuna::{
    decode::{Protocol, details, summarize},
    packet::{LinkType, PacketRecord},
};

fn packet(link: u16, bytes: Vec<u8>) -> PacketRecord {
    PacketRecord::new(
        0,
        LinkType(link),
        None,
        bytes.len() as u32,
        bytes.into_boxed_slice(),
    )
    .unwrap()
}

#[test]
fn decodes_vlan_ipv4_tcp_with_packet_relative_field_ranges() {
    let mut frame = vec![0; 18 + 24 + 20 + 3];
    frame[12..18].copy_from_slice(&[0x81, 0, 0, 42, 8, 0]);
    frame[18] = 0x46;
    frame[20..22].copy_from_slice(&47u16.to_be_bytes());
    frame[27] = 6;
    frame[30..38].copy_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    frame[42..46].copy_from_slice(&[0x12, 0x34, 0, 80]);
    frame[54] = 0x50;
    let packet = packet(1, frame);
    let summary = summarize(&packet);
    assert_eq!(summary.protocol, Protocol::Tcp);
    assert!(summary.has(Protocol::Vlan));
    assert!(summary.has(Protocol::Ipv4));
    assert_eq!(summary.source.unwrap().to_string(), "192.0.2.1");
    assert_eq!(summary.destination_port, Some(80));
    assert_eq!(summary.tcp.unwrap().payload_offset, 62);
    assert_eq!(summary.tcp.unwrap().captured_payload_len, 3);
    let details = details(&packet);
    let dst = details
        .layers
        .last()
        .unwrap()
        .fields
        .iter()
        .find(|field| field.key == "tcp.dstport")
        .unwrap();
    assert_eq!((dst.offset, dst.len), (44, 2));
}

#[test]
fn handles_ipv6_extensions_and_refuses_ports_from_later_fragments() {
    let mut bytes = vec![0; 56];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&16u16.to_be_bytes());
    bytes[6] = 44;
    bytes[40] = 17;
    bytes[50..54].copy_from_slice(&[0, 53, 0, 8]);
    assert_eq!(
        summarize(&packet(101, bytes.clone())).destination_port,
        Some(53)
    );
    bytes[43] = 8;
    let decoded = summarize(&packet(101, bytes));
    assert!(decoded.fragmented);
    assert_eq!(decoded.protocol, Protocol::Ipv6);
    assert_eq!(decoded.destination_port, None);
}

#[test]
fn reported_field_ranges_are_valid_for_every_truncated_prefix() {
    let bytes = [
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0x01, 0x11, 0x01,
        0x12, 0, 8, 0, 0,
    ];
    for len in 0..=bytes.len() {
        let packet = packet(101, bytes[..len].to_vec());
        let decoded = details(&packet);
        assert!(
            decoded
                .layers
                .iter()
                .flat_map(|layer| &layer.fields)
                .all(|field| field.offset + field.len <= len)
        );
        if len < bytes.len() {
            assert!(decoded.summary.issue.is_some());
        }
    }
    assert!(summarize(&packet(65000, bytes.to_vec())).issue.is_some());
}
