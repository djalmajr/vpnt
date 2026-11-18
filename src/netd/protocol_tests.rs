use super::*;
use serde_json::{Value, json};

fn valid() -> Value {
    json!({"op":"configure","ifname":"vpnt0","address":"10.1.2.3","prefix":18,
        "mtu":1500,"routes":[{"network":"10.0.0.0","prefix":8}],
        "dns":{"servers":["10.200.0.1"],"domains":["serpro"]}})
}
fn parse(value: &Value) -> Result<Request, ErrorCode> {
    parse_request(format!("{value}\n").as_bytes())
}
fn checked(value: &Value) -> Result<Config, ErrorCode> {
    match parse(value)? {
        Request::Configure(c) => c.validate(),
        _ => panic!("expected configure"),
    }
}
#[test]
fn requests_round_trip_and_default_mtu() {
    for value in [
        json!({"op":"hello","version":1}),
        json!({"op":"open_tun"}),
        valid(),
        json!({"op":"close_tun","ifname":"vpnt0"}),
    ] {
        assert_eq!(serde_json::to_value(parse(&value).unwrap()).unwrap(), value);
    }
    let mut v = valid();
    v.as_object_mut().unwrap().remove("mtu");
    assert_eq!(checked(&v).unwrap().mtu, 1500);
    for name in ["vpnt0", "vpnt1", "vpnt9", "vpnt10", "vpnt99"] {
        assert_eq!(TunName::parse(name).unwrap().to_string(), name);
    }
}
#[test]
fn responses_exact_wire() {
    for (response, expected) in [
        (Response::Ok, "{\"ok\":true}\n"),
        (Response::Version(1), "{\"ok\":true,\"version\":1}\n"),
        (
            Response::Opened(TunName::parse("vpnt0").unwrap()),
            "{\"ok\":true,\"ifname\":\"vpnt0\"}\n",
        ),
        (
            Response::Error(ErrorCode::Backend),
            "{\"ok\":false,\"error\":\"backend\"}\n",
        ),
    ] {
        assert_eq!(encode_response(&response), expected.as_bytes());
    }
    for (code, name) in [
        (ErrorCode::BadRequest, "bad_request"),
        (ErrorCode::UnsupportedVersion, "unsupported_version"),
        (ErrorCode::NotOwned, "not_owned"),
        (ErrorCode::Limit, "limit"),
        (ErrorCode::InvalidAddress, "invalid_address"),
        (ErrorCode::InvalidRoute, "invalid_route"),
        (ErrorCode::InvalidDns, "invalid_dns"),
        (ErrorCode::Backend, "backend"),
    ] {
        assert_eq!(
            encode_response(&Response::Error(code)),
            format!("{{\"ok\":false,\"error\":\"{name}\"}}\n").as_bytes()
        );
    }
}
#[test]
fn framing_and_unknown_fields() {
    let mut line = b"{\"op\":\"open_tun\"}".to_vec();
    line.resize(MAX_LINE - 1, b' ');
    line.push(b'\n');
    assert!(parse_request(&line).is_ok());
    line.insert(0, b' ');
    assert_eq!(parse_request(&line).unwrap_err(), ErrorCode::BadRequest);
    for bytes in [
        b"\xff\n".as_slice(),
        b"{}\n",
        b"{\"op\":\"open_tun\"}",
        b"{\"op\":\"open_tun\"}\n{}\n",
        b"{\"op\":\"open_tun\",\"extra\":0}\n",
    ] {
        assert_eq!(parse_request(bytes).unwrap_err(), ErrorCode::BadRequest);
    }
    assert_eq!(
        parse(&json!({"op":"hello","version":2})).unwrap_err(),
        ErrorCode::UnsupportedVersion
    );
    for path in ["/extra", "/routes/0/extra", "/dns/extra"] {
        let mut v = valid();
        let (parent, _) = path.rsplit_once('/').unwrap();
        v.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(0));
        assert_eq!(parse(&v).unwrap_err(), ErrorCode::BadRequest);
    }
    for name in [
        "vpnt00", "vpnt01", "vpnt123", "vpnt", "vpnt-1", "vpnt١", "vpnt1\n", "vpnt1;id",
    ] {
        assert_eq!(TunName::parse(name).unwrap_err(), ErrorCode::BadRequest);
        assert_eq!(
            parse(&json!({"op":"close_tun","ifname":name})).unwrap_err(),
            ErrorCode::BadRequest
        );
    }
}
#[test]
fn address_and_mtu_rules() {
    for address in [
        "0.0.0.0",
        "0.1.2.3",
        "255.255.255.255",
        "224.0.0.1",
        "239.1.1.1",
        "127.0.0.1",
        "::1",
        "garbage",
    ] {
        let mut v = valid();
        v["address"] = json!(address);
        assert_eq!(
            checked(&v).unwrap_err(),
            ErrorCode::InvalidAddress,
            "{address}"
        );
    }
    for (key, values) in [("prefix", vec![0, 33]), ("mtu", vec![575, 9001])] {
        for value in values {
            let mut v = valid();
            v[key] = json!(value);
            assert_eq!(
                checked(&v).unwrap_err(),
                ErrorCode::InvalidAddress,
                "{key}={value}"
            );
        }
    }
    for (mtu, prefix) in [(576, 1), (9000, 32)] {
        let mut v = valid();
        v["mtu"] = json!(mtu);
        v["prefix"] = json!(prefix);
        assert!(checked(&v).is_ok());
    }
}
#[test]
fn route_rules() {
    for route in [
        json!({"network":"10.0.0.0","prefix":7}),
        json!({"network":"10.0.0.0","prefix":33}),
        json!({"network":"10.0.0.1","prefix":8}),
        json!({"network":"0.0.0.0","prefix":8}),
        json!({"network":"127.0.0.0","prefix":8}),
        json!({"network":"224.0.0.0","prefix":8}),
        json!({"network":"::1","prefix":32}),
        json!({"network":"bad","prefix":8}),
    ] {
        let mut v = valid();
        v["routes"] = json!([route]);
        assert_eq!(checked(&v).unwrap_err(), ErrorCode::InvalidRoute, "{v}");
    }
    let mut v = valid();
    v["routes"] = json!([v["routes"][0].clone(), v["routes"][0].clone()]);
    assert_eq!(checked(&v).unwrap_err(), ErrorCode::InvalidRoute);
    v["routes"] = json!(
        (0..257)
            .map(|i| json!({"network":format!("10.{}.{}.0",i/256,i%256),"prefix":24}))
            .collect::<Vec<_>>()
    );
    assert_eq!(checked(&v).unwrap_err(), ErrorCode::InvalidRoute);
    v["routes"].as_array_mut().unwrap().pop();
    assert_eq!(checked(&v).unwrap().routes.len(), 256);
}
#[test]
fn dns_rules() {
    for domain in [
        "~serpro", "Serpro", "-serpro", "serpro-", ".serpro", "serpro.", "a..b", "", "a_b", "é",
    ] {
        let mut v = valid();
        v["dns"]["domains"] = json!([domain]);
        assert_eq!(checked(&v).unwrap_err(), ErrorCode::InvalidDns, "{domain}");
    }
    for domains in [
        vec!["a".repeat(64)],
        vec!["a".into(), "a".into()],
        vec!["a".repeat(63); 4],
        (0..17).map(|i| format!("d{i}")).collect(),
    ] {
        let mut v = valid();
        v["dns"]["domains"] = json!(domains);
        assert_eq!(checked(&v).unwrap_err(), ErrorCode::InvalidDns);
    }
    for server in [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "bad",
    ] {
        let mut v = valid();
        v["dns"]["servers"] = json!([server]);
        assert_eq!(checked(&v).unwrap_err(), ErrorCode::InvalidDns);
    }
    let mut v = valid();
    v["dns"]["servers"] = json!(vec!["1.1.1.1"; 5]);
    assert_eq!(checked(&v).unwrap_err(), ErrorCode::InvalidDns);
    v["dns"]["servers"] = json!([]);
    assert_eq!(checked(&v).unwrap_err(), ErrorCode::InvalidDns);
    v["dns"]["domains"] = json!([]);
    assert!(checked(&v).is_ok());
    v["dns"]["servers"] = json!(vec!["1.1.1.1"; 4]);
    v["dns"]["domains"] = json!((0..16).map(|i| format!("d{i}")).collect::<Vec<_>>());
    assert!(checked(&v).is_ok());
    v["dns"]["domains"] = json!([format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    )]);
    assert!(checked(&v).is_ok());
}

#[test]
fn transport_encoders_round_trip_and_reject_inconsistent_responses() {
    for request in [
        json!({"op":"hello","version":1}),
        json!({"op":"open_tun"}),
        valid(),
        json!({"op":"close_tun","ifname":"vpnt0"}),
    ] {
        let bytes = encode_request(&parse(&request).unwrap());
        assert_eq!(
            serde_json::to_value(parse_request(&bytes).unwrap()).unwrap(),
            request
        );
    }
    for response in [
        Response::Ok,
        Response::Version(1),
        Response::Opened(TunName::parse("vpnt0").unwrap()),
        Response::Error(ErrorCode::NotOwned),
    ] {
        let bytes = encode_response(&response);
        assert_eq!(encode_response(&decode_response(&bytes).unwrap()), bytes);
    }
    for bad in [
        "{\"ok\":true,\"error\":\"limit\"}\n",
        "{\"ok\":false}\n",
        "{\"ok\":true,\"ifname\":\"vpnt00\"}\n",
        "{\"ok\":true,\"version\":1,\"extra\":0}\n",
        "{\"ok\":true}",
        "{\"ok\":true,\"ok\":false}\n",
    ] {
        assert_eq!(
            decode_response(bad.as_bytes()).unwrap_err(),
            ErrorCode::BadRequest
        );
    }
}
