use super::*;
use crate::netd::{
    protocol::parse_request,
    server::tests::{Fixture, configure},
};
use std::thread;

#[test]
fn all_requests_refusal_and_drop_against_server() {
    let fixture = Fixture::new(Duration::from_secs(1));
    thread::scope(|scope| {
        let worker = scope.spawn(|| fixture.accept(1000).unwrap().join().unwrap());
        let mut client = Client::connect(&fixture.path).unwrap();
        let first = client.open_tun().unwrap();
        assert_eq!(first.as_str(), "vpnt0");
        let Request::Configure(request) =
            parse_request(configure(first.as_str()).as_bytes()).unwrap()
        else {
            panic!("expected configure");
        };
        client.configure(&request.validate().unwrap()).unwrap();
        let second = client.open_tun().unwrap();
        assert!(matches!(
            client.open_tun(),
            Err(ClientError::Refused(ErrorCode::Limit))
        ));
        client.close_tun(&second).unwrap();
        assert!(matches!(
            client.close_tun(&second),
            Err(ClientError::Refused(ErrorCode::NotOwned))
        ));
        drop(client);
        worker.join().unwrap();
    });
    assert_eq!(
        *fixture.fake.events.lock().unwrap(),
        [
            "create vpnt0 1000",
            "configure vpnt0",
            "create vpnt1 1000",
            "delete vpnt1",
            "delete vpnt0"
        ]
    );
}
