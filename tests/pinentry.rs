use std::{cell::Cell, io::Cursor};
use vpnt::{
    helper::pinentry::{self, Error},
    secrets::Secret,
};

#[test]
fn openfortivpn_exchange_preserves_spaces_percent_plus_and_utf8() {
    let input=b"SETTITLE VPN Password\nSETDESC VPN Requires a Password\nSETKEYINFO arbitrary-untrusted-hint\nSETPROMPT Password%3A\nGETPIN\n";
    let calls = Cell::new(0);
    let mut output = Vec::new();
    pinentry::serve(&mut Cursor::new(input), &mut output, || {
        calls.set(calls.get() + 1);
        Ok(Secret::from(" %literal+é "))
    })
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        output,
        b"OK vpnt\nOK\nOK\nOK\nOK\nD %20%25literal+%C3%A9%20\nOK\n"
    );
}

#[test]
fn malformed_or_excessive_queries_never_obtain_a_secret() {
    for input in [
        b"GETPIN extra\n".to_vec(),
        b"GETPIN".to_vec(),
        b"SETDESC bad\0value\nGETPIN\n".to_vec(),
        b"UNKNOWN\n".to_vec(),
        vec![b'x'; 8193],
        b"SETTITLE value\n".repeat(33),
    ] {
        let mut output = Vec::new();
        let result = pinentry::serve(&mut Cursor::new(input), &mut output, || {
            panic!("invalid input must not request credentials")
        });
        assert!(result.is_err());
        assert!(!output.windows(2).any(|part| part == b"D "));
    }
}

#[test]
fn unavailable_or_oversized_credentials_only_emit_a_fixed_error() {
    for result in [
        Err(Error::Unavailable),
        Ok(Secret::from("x".repeat(257))),
        Ok(Secret::from("bad\nsecret")),
    ] {
        let mut output = Vec::new();
        assert!(pinentry::serve(&mut Cursor::new(b"GETPIN\n"), &mut output, || result).is_err());
        assert_eq!(output, b"OK vpnt\nERR 1 unavailable\n");
    }
}
