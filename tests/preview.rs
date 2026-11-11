#![cfg(feature = "desktop")]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Preview(Child);

impl Drop for Preview {
    fn drop(&mut self) {
        // This handle owns the child; no PID lookup or process-name matching.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(port: u16, host: &str, origin: &str, body: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(stream, "POST /api/command HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", body.len()).unwrap();
    stream.write_all(body).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

// Consumer boundary: a foreign document cannot mutate the demo, and malformed
// UTF-8 must not terminate the process before a subsequent valid command.
#[test]
fn demo_http_boundary_rejects_foreign_requests_and_survives_invalid_input() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut preview = Preview(
        Command::new(env!("CARGO_BIN_EXE_vpnt"))
            .args(["--demo-server", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(preview.0.try_wait().unwrap().is_none(), "preview exited");
        assert!(Instant::now() < deadline, "preview did not start");
        thread::sleep(Duration::from_millis(10));
    }
    let host = format!("127.0.0.1:{port}");
    let origin = format!("http://{host}");
    let valid = br#"{"id":"test-1","command":{"type":"get_snapshot"}}"#;
    assert!(request(port, &host, "https://foreign.example", valid).starts_with("HTTP/1.1 403"));
    assert!(request(port, "foreign.example", &origin, valid).starts_with("HTTP/1.1 403"));
    assert!(request(port, &host, &origin, b"\xff").starts_with("HTTP/1.1 400"));
    assert!(
        request(
            port,
            &host,
            &origin,
            br#"{"id":"test-1","command":{"type":"get_snapshot","extra":true}}"#
        )
        .starts_with("HTTP/1.1 400")
    );
    let response = request(port, &host, &origin, valid);
    assert!(response.starts_with("HTTP/1.1 200"));
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(value["id"], "test-1");
    assert_eq!(value["snapshot"]["demo"], true);
    assert_eq!(value["snapshot"]["vpns"][0]["state"], "off");
}
