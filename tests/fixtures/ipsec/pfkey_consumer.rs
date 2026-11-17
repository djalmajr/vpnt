use std::io::{self, Read};
use vpnt::connection::ipsec::pfkey::{Entry, Kind, decode};
use zeroize::Zeroizing;

fn main() {
    let mut bytes = Zeroizing::new(Vec::new());
    io::stdin().take(524_281).read_to_end(&mut bytes).unwrap();
    let result = decode(&bytes).expect("original Darwin NAT-T producer");
    assert_eq!(result.kind, Kind::Sad);
    let Entry::Sa(sa) = result.entry else {
        panic!("SA expected")
    };
    assert_eq!(sa.spi, 0x1234abcd, "network-endian SPI");
    assert_eq!(sa.reqid, 0x10001, "untruncated native reqid");
    assert_eq!(sa.natt_port, Some(4500), "native-endian NAT-T port");
    assert_eq!(sa.source.port, 4501, "network-endian sockaddr port");
    assert_eq!(sa.destination.port, 4500);
    let mode = std::env::args().nth(1).unwrap();
    assert_eq!(sa.source.address.ip.is_ipv6(), mode == "natt6");
    println!("original {mode} metadata admitted; no raw datagram retained");
}
