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

#[test]
fn decodes_dns_names_and_evaluates_typed_filters() {
    use wiretuna::filter::Filter;

    let dns = [
        0, 42, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0,
        0, 0, 30, 0, 4, 192, 0, 2, 1,
    ];
    let mut bytes = vec![0; 28];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(28 + dns.len() as u16).to_be_bytes());
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&[192, 0, 2, 53]);
    bytes[20..22].copy_from_slice(&53u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&(8 + dns.len() as u16).to_be_bytes());
    bytes.extend(dns);
    let decoded = details(&packet(101, bytes.clone()));
    assert_eq!(decoded.summary.protocol, Protocol::Dns);
    assert!(
        decoded
            .layers
            .last()
            .unwrap()
            .fields
            .iter()
            .any(|field| field.key == "dns.a" && field.value == "192.0.2.1")
    );
    assert!(
        Filter::parse("tcp || (dns && ip.src == 192.0.2.53 && udp.srcport == 53)")
            .unwrap()
            .matches(&decoded.summary)
    );
    assert!(
        !Filter::parse("tcp.srcport == 53")
            .unwrap()
            .matches(&decoded.summary)
    );
    assert!(Filter::parse("udp.srcport == 70000").is_err());
    assert!(Filter::parse("ip.src == ::1").is_err());

    bytes[48] = 19;
    assert!(details(&packet(101, bytes)).summary.issue.is_some());
}

fn udp_quic(destination: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = [
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0xc0, 0x01, 0, 0, 0,
        0, 0, 0,
    ]
    .to_vec();
    bytes[2..4].copy_from_slice(&(28 + payload.len() as u16).to_be_bytes());
    bytes[22..24].copy_from_slice(&destination.to_be_bytes());
    bytes[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn identifies_quic_versions_and_coalesced_packets_without_reading_protected_fields() {
    use wiretuna::filter::Filter;

    let mut datagram = vec![0xc0, 0, 0, 0, 1, 2, 0xca, 0xfe, 1, 0xae, 0, 20];
    datagram.extend_from_slice(&[0; 20]);
    datagram.extend_from_slice(&[0xe0, 0, 0, 0, 1, 0, 0, 0x40, 20]);
    datagram.extend_from_slice(&[0; 20]);
    let bytes = udp_quic(4444, &datagram);
    let decoded_packet = packet(101, bytes.clone());
    let summary = summarize(&decoded_packet);
    assert!(summary.has(Protocol::Quic) && summary.has(Protocol::Udp));
    assert!(Filter::parse("quic && udp").unwrap().matches(&summary));
    let decoded = details(&decoded_packet);
    let layers: Vec<_> = decoded
        .layers
        .iter()
        .filter(|layer| layer.name == "QUIC")
        .collect();
    assert_eq!(layers.len(), 2);
    assert_eq!(layers[0].fields[0].value, "Initial");
    assert_eq!(layers[1].fields[0].value, "Handshake");
    for length in 0..=bytes.len() {
        let detail = details(&packet(101, bytes[..length].to_vec()));
        assert!(
            detail
                .layers
                .iter()
                .flat_map(|layer| &layer.fields)
                .all(|field| field.offset + field.len <= length)
        );
    }

    let mut v2 = vec![0xd0, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 20];
    v2.extend_from_slice(&[0; 20]);
    let decoded = details(&packet(101, udp_quic(443, &v2)));
    assert_eq!(decoded.layers.last().unwrap().fields[0].value, "Initial");
    assert_eq!(decoded.layers.last().unwrap().fields[1].value, "0x6b3343cf");
}

#[test]
fn limits_heuristic_quic_detection_and_displays_version_negotiation() {
    let negotiation = [
        0x80, 0, 0, 0, 0, 1, 0xce, 0, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf,
    ];
    for port in [443, 8000] {
        let decoded = details(&packet(101, udp_quic(port, &negotiation)));
        if port == 443 {
            let fields = &decoded.layers.last().unwrap().fields;
            assert_eq!(fields[0].value, "Version Negotiation");
            assert_eq!(
                fields
                    .iter()
                    .filter(|field| field.key == "quic.supported_version")
                    .count(),
                2
            );
        } else {
            assert_eq!(decoded.summary.protocol, Protocol::Udp);
        }
    }
    let short = [0x40, 0, 0, 0, 1, 0, 0, 0];
    assert_eq!(
        summarize(&packet(101, udp_quic(443, &short))).protocol,
        Protocol::Udp
    );
}
