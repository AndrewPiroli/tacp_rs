use pcap_file::pcap::*;
use tacp::*;

const PCAPS: &[(&str, &[u8], &[u8])] = &[
    ("werberblog.net_tacacs.pcap", include_bytes!("../pcaps/werberblog.net_tacacs.pcap"), b"John3.16")
];

/// Checks that we can parse all TACACS packets out of all embedded pcaps.
pub fn check_pcap() -> bool {
    for (_name, pcap, tacacs_key) in PCAPS {
        let cur = std::io::Cursor::new(*pcap);
        let mut reader = PcapReader::new(cur).unwrap();
        while let Some(pkt) = reader.next_packet() {
            if let Ok(pkt) = pkt {
                let srcprt = u16::from_be_bytes([pkt.data[34], pkt.data[35]]);
                let dstprt = u16::from_be_bytes([pkt.data[36], pkt.data[37]]);
                if (srcprt == 49 || dstprt == 49) && pkt.data.len() > 60 && !parse_tacacs_pkt(&pkt.data[54..], tacacs_key) {
                    return false;
                }
            }
        }
    }
    true
}

fn parse_tacacs_pkt(data: &[u8], key: &[u8]) -> bool {
    if data.len() < 12 { return false; }
    if let Ok(header) = PacketHeader::try_ref_from_bytes(&data[..12]) {
        let mut body = Vec::from(&data[12..]).into_boxed_slice();
        tacp::obfuscation::obfuscate_in_place(header, key, &mut body);
        return match header.ty {
            PacketType::AUTHEN => try_parse_authen(&body),
            PacketType::AUTHOR => try_parse_author(&body),
            PacketType::ACCT => try_parse_acct(&body),
        };
    }
    false
}

fn try_parse_authen(data: & [u8]) -> bool {
    AuthenStartPacket::try_ref_from_bytes(data).is_ok() ||
    AuthenReplyPacket::try_ref_from_bytes(data).is_ok() ||
    AuthenContinuePacket::try_ref_from_bytes(data).is_ok()
}

fn try_parse_author(data: &[u8]) -> bool {
    AuthorRequestPacket::try_ref_from_bytes(data).is_ok() ||
    AuthorReplyPacket::try_ref_from_bytes(data).is_ok()
}

fn try_parse_acct(data: &[u8]) -> bool {
    AcctRequestPacket::try_ref_from_bytes(data).is_ok() ||
    AcctReplyPacket::try_ref_from_bytes(data).is_ok()
}