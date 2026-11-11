use crate::{
    app::App,
    assets::{CONTENT_SECURITY_POLICY, asset},
    bridge::{Reply, parse_request},
};
use std::io::Cursor;
use tiny_http::{Header, Method, Response, Server};
use zeroize::Zeroizing;

/// Explicit demo server for browser validation. It never constructs a real VPN backend.
pub fn serve(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = Server::http((std::net::Ipv4Addr::LOCALHOST, port))?;
    let mut app = App::demo();
    println!("vpnt demo: http://127.0.0.1:{port}");
    for mut request in server.incoming_requests() {
        let host = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("Host"))
            .map(|header| header.value.as_str());
        let expected_host = format!("127.0.0.1:{port}");
        let expected_origin = format!("http://{expected_host}");
        let origin = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("Origin"));
        if host != Some(expected_host.as_str())
            || origin.is_some_and(|header| header.value.as_str() != expected_origin)
        {
            let _ = request.respond(Response::empty(403));
            continue;
        }
        if request.method() == &Method::Post && request.url() == "/api/command" {
            let content_type = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("Content-Type"));
            if !content_type.is_some_and(|header| {
                header
                    .value
                    .as_str()
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim() == "application/json")
            }) {
                let _ = request.respond(Response::empty(415));
                continue;
            }
            let mut body = Zeroizing::new(String::new());
            if request
                .as_reader()
                .take(65537)
                .read_to_string(&mut body)
                .is_err()
            {
                let _ = request.respond(Response::empty(400));
                continue;
            }
            let reply = match parse_request(&body) {
                Ok(input) => match app.dispatch(input.command) {
                    Ok(snapshot) => Reply {
                        id: input.id,
                        snapshot: Some(snapshot),
                        error: None,
                    },
                    Err(error) => Reply {
                        id: input.id,
                        snapshot: None,
                        error: Some(error.into()),
                    },
                },
                Err(_) => {
                    let _ = request.respond(Response::empty(400));
                    continue;
                }
            };
            let _ = request.respond(
                Response::from_string(serde_json::to_string(&reply)?)
                    .with_header(Header::from_bytes("Content-Type", "application/json").unwrap()),
            );
        } else if request.method() == &Method::Get {
            if let Some((mime, body)) = asset(request.url()) {
                let response = Response::new(
                    200.into(),
                    vec![
                        Header::from_bytes("Content-Type", mime).unwrap(),
                        Header::from_bytes("Content-Security-Policy", CONTENT_SECURITY_POLICY)
                            .unwrap(),
                    ],
                    Cursor::new(body),
                    Some(body.len()),
                    None,
                );
                let _ = request.respond(response);
            } else {
                let _ = request.respond(Response::empty(404));
            }
        } else {
            let _ = request.respond(Response::empty(405));
        }
    }
    Ok(())
}

use std::io::Read;
