use super::*;
fn sockaddr(ip: &str) -> Vec<u8> {
    let ip: IpAddr = ip.parse().unwrap();
    let mut result = vec![0; if ip.is_ipv4() { 16 } else { 28 }];
    result[0] = result.len() as u8;
    match ip {
        IpAddr::V4(ip) => {
            result[1] = libc::AF_INET as u8;
            result[4..8].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            result[1] = libc::AF_INET6 as u8;
            result[8..24].copy_from_slice(&ip.octets());
        }
    }
    result
}
fn fixture() -> Vec<u8> {
    let destination = sockaddr("10.20.0.0");
    let gateway = sockaddr("192.0.2.1");
    let mask = vec![7, 0, 0, 0, 255, 255, 0, 0];
    let mut result = vec![0u8; DUMP];
    result[2] = libc::RTM_VERSION as u8;
    result[3] = libc::RTM_GET2 as u8;
    put16(&mut result, offset_of!(libc::rt_msghdr, rtm_index), 3);
    put32(
        &mut result,
        offset_of!(libc::rt_msghdr, rtm_flags),
        (libc::RTF_UP | libc::RTF_GATEWAY | libc::RTF_IFSCOPE) as u32,
    );
    put32(
        &mut result,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        (libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK) as u32,
    );
    result.extend(destination);
    result.extend(gateway);
    result.extend(mask);
    let length = result.len();
    put16(&mut result, 0, length as u16);
    result
}
#[test]
fn compact_masks_scope_and_every_truncation_are_checked() {
    let bytes = fixture();
    let result = record(frame(&bytes).unwrap(), DUMP).unwrap();
    assert_eq!(result.key.network, "10.20.0.0/16".parse().unwrap());
    assert_eq!(result.key.scope, 3);
    assert_eq!(result.interface, 3);
    assert_eq!(
        result.gateway,
        Some(Gateway::Address(Address::unscoped(
            "192.0.2.1".parse().unwrap()
        )))
    );
    assert_eq!(
        result
            .gateway_pin(Address::unscoped("10.20.8.9".parse().unwrap()))
            .unwrap()
            .key
            .network,
        Network::host("10.20.8.9".parse().unwrap())
    );
    for length in 0..bytes.len() {
        assert!(
            frame(&bytes[..length])
                .and_then(|frame| record(frame, DUMP))
                .is_err(),
            "truncation {length}"
        );
    }
    let mut wrong = bytes.clone();
    let end = wrong.len();
    wrong[end - 2] = 1;
    assert!(record(&wrong, DUMP).is_err());
    let mut wrong = bytes.clone();
    put16(&mut wrong, offset_of!(libc::rt_msghdr, rtm_index), 0);
    assert!(record(&wrong, DUMP).is_err());
    let mut wrong = bytes.clone();
    wrong[2] = 0;
    assert!(frame(&wrong).is_err());
}
#[test]
fn native_queries_are_get_only_and_ipv6_zones_are_not_lost() {
    let address = Address {
        ip: "fe80::1".parse().unwrap(),
        zone: 7,
    };
    let bytes = query(address, 7, 42, 19).unwrap();
    assert_eq!(bytes[3], libc::RTM_GET as u8);
    assert_eq!(frame(&bytes).unwrap().len(), bytes.len());
    assert_eq!(
        signed(&bytes, offset_of!(libc::rt_msghdr, rtm_seq)).unwrap(),
        19
    );
    assert_eq!(ip(&bytes[CLASSIC..CLASSIC + 28]).unwrap(), address);
    assert!(query(address, 8, 42, 19).is_err());
    let mut embedded = sockaddr("fe80::1");
    embedded[10..12].copy_from_slice(&7u16.to_be_bytes());
    assert_eq!(ip(&embedded).unwrap(), address);
    put32(&mut embedded, 24, 8);
    assert!(ip(&embedded).is_err());
}
