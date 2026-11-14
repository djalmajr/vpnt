use super::*;
use crate::helper::server::caller::Caller;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
};
#[test]
fn removal_channel_uses_kernel_identity_and_refuses_an_extra_uid_or_second_document() {
    for case in ["uid", "duplicate", "valid"] {
        let mut f = Fixture::new();
        let uid = unsafe { libc::getuid() };
        let other = if uid == 601 { 602 } else { 601 };
        f.recipient(other);
        f.activate().unwrap();
        f.recipient(uid);
        f.activate().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(4)))
            .unwrap();
        std::thread::scope(|scope| {
            let executor = &mut f.executor;
            let task = scope.spawn(move || {
                let caller = Caller::from_fd(server.into()).unwrap();
                assert_eq!(caller.uid, unsafe { libc::getuid() });
                access::channel::serve(caller, executor)
            });
            let mut read = BufReader::new(client.try_clone().unwrap());
            let mut ready = String::new();
            read.read_line(&mut ready).unwrap();
            let ready: serde_json::Value = serde_json::from_str(&ready).unwrap();
            assert_eq!(ready["type"], "ready");
            assert_eq!(ready["format"], 1);
            let document = match case {
                "uid" => format!("{{\"id\":\"remove-1\",\"uid\":{other}}}\n"),
                "duplicate" => "{\"id\":\"remove-1\"}\n{\"id\":\"remove-2\"}\n".into(),
                _ => "{\"id\":\"remove-1\"}\n".into(),
            };
            client.write_all(document.as_bytes()).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut reply = String::new();
            read.read_line(&mut reply).unwrap();
            let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(
                reply["type"],
                if case == "valid" { "removed" } else { "failed" }
            );
            assert!(!reply.to_string().contains(&other.to_string()));
            let mut tail = Vec::new();
            read.read_to_end(&mut tail).unwrap();
            assert!(tail.is_empty());
            let result = task.join().unwrap();
            assert!(result.is_ok(), "{case}: {result:?}");
        });
        let receipt = Receipt::load(&f.executor.tree).unwrap().unwrap();
        assert!(receipt.users.contains_key(&other));
        assert_eq!(receipt.users.contains_key(&uid), case != "valid");
    }
}
