use super::*;
use std::{os::unix::net::UnixDatagram, thread};

fn put(packet: &mut [u8], offset: usize, value: i32) {
    packet[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}
#[test]
fn get_consumer_filters_foreign_pid_and_sequence_and_refuses_truncation() {
    // Mutation: accept another query's PID/sequence, or parse an incomplete
    // frame. This uses the actual Reader loop over a private datagram pair.
    for truncate in [false, true] {
        let (client, peer) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let worker = thread::spawn(move || {
            let mut packet = vec![0u8; 65_536];
            let length = peer.recv(&mut packet).unwrap();
            packet.truncate(length);
            assert_eq!(packet[3], libc::RTM_GET as u8);
            put(
                &mut packet,
                offset_of!(libc::rt_msghdr, rtm_flags),
                libc::RTF_UP | libc::RTF_HOST,
            );
            packet[offset_of!(libc::rt_msghdr, rtm_index)
                ..offset_of!(libc::rt_msghdr, rtm_index) + 2]
                .copy_from_slice(&1u16.to_ne_bytes());
            if truncate {
                peer.send(&packet[..4]).unwrap();
                return;
            }
            for field in [
                offset_of!(libc::rt_msghdr, rtm_pid),
                offset_of!(libc::rt_msghdr, rtm_seq),
            ] {
                let mut foreign = packet.clone();
                let value = codec::signed(&foreign, field).unwrap();
                put(&mut foreign, field, value + 1);
                foreign[offset_of!(libc::rt_msghdr, rtm_index)
                    ..offset_of!(libc::rt_msghdr, rtm_index) + 2]
                    .copy_from_slice(&9u16.to_ne_bytes());
                peer.send(&foreign).unwrap();
            }
            peer.send(&packet).unwrap();
        });
        let mut reader = Reader { fd: client.into() };
        let result = reader.lookup(
            Address::unscoped("127.0.0.1".parse().unwrap()),
            0,
            Duration::from_secs(1),
            &AtomicBool::new(false),
        );
        worker.join().unwrap();
        if truncate {
            assert!(matches!(result, Err(Error::Invalid)));
        } else {
            assert_eq!(result.unwrap().interface, 1);
        }
    }
}
#[test]
fn native_table_and_get_queries_agree_on_loopback_without_mutation() {
    let name = std::ffi::CString::new("lo0").unwrap();
    // SAFETY: name is a live NUL-terminated interface name.
    let loopback = unsafe { libc::if_nametoindex(name.as_ptr()) };
    assert_ne!(loopback, 0);
    let snapshot = Snapshot::read().unwrap();
    assert!(!snapshot.records.is_empty());
    let mut reader = Reader::open().unwrap();
    for value in ["127.0.0.1", "::1"] {
        let address = Address::unscoped(value.parse().unwrap());
        let route = reader
            .lookup(address, 0, Duration::from_secs(1), &AtomicBool::new(false))
            .unwrap();
        assert_eq!(route.interface as u32, loopback);
        assert!(route.key.network.contains(address.ip));
        assert!(
            snapshot
                .records
                .iter()
                .any(|record| record.interface == route.interface
                    && record.key.network.contains(address.ip))
        );
    }
    assert!(matches!(
        reader.lookup(
            Address::unscoped("127.0.0.1".parse().unwrap()),
            0,
            Duration::from_secs(1),
            &AtomicBool::new(true)
        ),
        Err(Error::Canceled)
    ));
}
