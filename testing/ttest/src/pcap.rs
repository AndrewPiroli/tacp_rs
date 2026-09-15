use pcap_file::pcap::*;
use tacp::*;

const PCAPS: &[(&str, &[u8], &[u8])] = &[(
    "werberblog.net_tacacs.pcap",
    include_bytes!("../pcaps/werberblog.net_tacacs.pcap"),
    b"John3.16",
)];

#[test]
fn embedded_pcaps_can_be_parsed() {
    for (name, pcap, tacacs_key) in PCAPS {
        let cursor = std::io::Cursor::new(*pcap);
        let mut reader = PcapReader::new(cursor)
            .unwrap_or_else(|error| panic!("failed to open `{name}`: {error}"));
        let mut packet_count = 0;
        while let Some(packet) = reader.next_packet() {
            let packet = packet
                .unwrap_or_else(|error| panic!("failed reading a packet from `{name}`: {error}"));
            let data = packet.data();
            if data.len() <= 60 {
                continue;
            }
            let src_port = u16::from_be_bytes([data[34], data[35]]);
            let dst_port = u16::from_be_bytes([data[36], data[37]]);
            if src_port == 49 || dst_port == 49 {
                packet_count += 1;
                assert!(
                    parse_tacacs_packet(&data[54..], tacacs_key),
                    "failed to parse TACACS+ packet {packet_count} from `{name}`"
                );
            }
        }
        assert!(packet_count > 0, "`{name}` contained no TACACS+ packets");
    }
}

fn parse_tacacs_packet(data: &[u8], key: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    let Ok(header) = PacketHeader::try_from_bytes_ref(&data[..12]) else {
        return false;
    };
    let body_len = header.length.get() as usize;
    if data.len() < 12 + body_len {
        return false;
    }
    let mut body = data[12..12 + body_len].to_vec().into_boxed_slice();
    tacp::obfuscation::obfuscate_in_place(header, key, &mut body);
    match header.ty {
        PacketType::AUTHEN => try_parse_authen(&body),
        PacketType::AUTHOR => try_parse_author(&body),
        PacketType::ACCT => try_parse_acct(&body),
    }
}

fn try_parse_authen(data: &[u8]) -> bool {
    AuthenStartPacket::try_from_bytes_ref(data).is_ok()
        || AuthenReplyPacket::try_from_bytes_ref(data).is_ok()
        || AuthenContinuePacket::try_from_bytes_ref(data).is_ok()
}

fn try_parse_author(data: &[u8]) -> bool {
    AuthorRequestPacket::try_from_bytes_ref(data).is_ok()
        || AuthorReplyPacket::try_from_bytes_ref(data).is_ok()
}

fn try_parse_acct(data: &[u8]) -> bool {
    AcctRequestPacket::try_from_bytes_ref(data).is_ok()
        || AcctReplyPacket::try_from_bytes_ref(data).is_ok()
}
