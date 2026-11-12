use super::*;
fn ne16(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_ne_bytes());
}
fn finish(mut b: Vec<u8>) -> Vec<u8> {
    let n = b.len() / 8;
    ne16(&mut b, 4, n as u16);
    b
}
fn at(b: &[u8], kind: u16) -> (usize, usize) {
    let mut p = 16;
    loop {
        let n = usize::from(u16::from_ne_bytes(b[p..p + 2].try_into().unwrap())) * 8;
        if u16::from_ne_bytes(b[p + 2..p + 4].try_into().unwrap()) == kind {
            return (p, n);
        }
        p += n;
    }
}
fn replace(b: &[u8], kind: u16, mut value: Vec<u8>) -> Vec<u8> {
    let (p, n) = at(b, kind);
    let m = value.len() / 8;
    ne16(&mut value, 0, m as u16);
    let mut out = b[..p].to_vec();
    out.extend(value);
    out.extend(&b[p + n..]);
    finish(out)
}
fn rejected(b: &[u8], label: &str) {
    assert_eq!(decode(b), Err(Error::Invalid), "{label}");
}

// Mutations: omit envelope/ext size, version, kind, satype, duplicate or key
// shape validation, or accept an errno with an echoed data payload.
#[test]
fn malformed_envelopes_and_extensions_never_publish_metadata() {
    let f = Fixture::new();
    let original = f.bytes("sa4");
    for n in 0..original.len() {
        rejected(&original[..n], "truncation");
    }
    for (position, value) in [(0, 1), (1, 0), (3, 4), (2, libc::ENOENT as u8)] {
        let mut b = original.clone();
        b[position] = value;
        rejected(&b, "envelope field");
    }
    for length in [
        0,
        1,
        (original.len() / 8 - 1) as u16,
        (original.len() / 8 + 1) as u16,
    ] {
        let mut b = original.clone();
        ne16(&mut b, 4, length);
        rejected(&b, "declared frame length");
    }
    for kind in [1, 19, 2, 5, 8] {
        let (p, n) = at(&original, kind);
        let mut b = original.clone();
        b.extend_from_slice(&original[p..p + n]);
        rejected(&finish(b), "duplicate extension");
    }
    for (kind, size) in [(1, 8), (1, 32), (19, 8), (19, 24), (2, 8), (2, 40)] {
        let (p, n) = at(&original, kind);
        let mut ext = original[p..p + n].to_vec();
        ext.resize(size, 0);
        rejected(&replace(&original, kind, ext), "fixed extension size");
    }
    for (field, value) in [(0, 0), (2, 0), (4, 256), (4, 0)] {
        let mut b = original.clone();
        let (p, _) = at(&b, 8);
        ne16(&mut b, p + field, value);
        rejected(&b, "key extension shape");
    }
    let mut b = original.clone();
    let (p, _) = at(&b, 1);
    b[p + 9] = 4;
    rejected(&b, "SA state");
    let mut b = original.clone();
    let (p, _) = at(&b, 19);
    b[p + 4] = 3;
    rejected(&b, "SA mode");
    let mut b = original.clone();
    let (p, _) = at(&b, 1);
    b[p + 12] = 2;
    rejected(&b, "NAT flag without extended port");
    let mut spd = f.bytes("spd4");
    spd[3] = 3;
    rejected(&spd, "SPD satype");
    let mut error = f.bytes("error");
    error.extend_from_slice(&[0; 8]);
    rejected(&finish(error), "errno payload");
    let policy = f.bytes("spd4");
    let (p, n) = at(&policy, 18);
    let mut b = original.clone();
    b.extend_from_slice(&policy[p..p + n]);
    rejected(&finish(b), "policy in SA record");
    let (p, n) = at(&original, 1);
    let mut b = policy;
    b.extend_from_slice(&original[p..p + n]);
    rejected(&finish(b), "SA in policy record");
}

// Mutations: accept invalid sockaddr sizes/families/prefixes, conflicting KAME
// scopes, mixed family policies, reversed ranges or two selector encodings.
#[test]
fn selectors_and_scopes_are_validated_without_normalizing_away_ambiguity() {
    let f = Fixture::new();
    for mode in ["sa4", "sa6", "spd4", "spd6"] {
        let original = f.bytes(mode);
        let (p, _) = at(&original, 5);
        for (offset, value) in [(5, 255), (8, 0), (8, 15), (9, 0)] {
            let mut b = original.clone();
            b[p + offset] = value;
            rejected(&b, "address shape");
        }
        let (_, n) = at(&original, 5);
        let mut ext = original[p..p + n].to_vec();
        ext.extend_from_slice(&[0; 8]);
        rejected(&replace(&original, 5, ext), "address trailing bytes");
    }
    let mut b = f.bytes("sa6-scoped");
    let (p, _) = at(&b, 5);
    b[p + 8 + 24..p + 8 + 28].copy_from_slice(&8u32.to_ne_bytes());
    rejected(&b, "conflicting scope");
    let v4 = f.bytes("sa4");
    let v6 = f.bytes("sa6");
    let (p, n) = at(&v6, 6);
    rejected(
        &replace(&v4, 6, v6[p..p + n].to_vec()),
        "SA family mismatch",
    );
    let v4 = f.bytes("spd4");
    let v6 = f.bytes("spd6");
    let (p, n) = at(&v6, 6);
    rejected(
        &replace(&v4, 6, v6[p..p + n].to_vec()),
        "policy family mismatch",
    );
    let mut b = f.bytes("spd4");
    let (p, _) = at(&b, 6);
    b[p + 4] = 17;
    rejected(&b, "selector protocols differ");
    let range = f.bytes("range");
    for (offset, value) in [(4, 17), (5, 32), (8 + 4, 9)] {
        let mut b = range.clone();
        let (p, _) = at(&b, 24);
        b[p + offset] = value;
        rejected(&b, "range disagreement");
    }
    let mut b = range.clone();
    let normal = f.bytes("spd4");
    let (p, n) = at(&normal, 5);
    b.extend_from_slice(&normal[p..p + n]);
    rejected(&finish(b), "both range and ordinary selector");
}

// Mutations: treat request length as words, accept unknown mode/protocol/level,
// ignore request tails, or permit a non-IPsec policy to smuggle SA requests.
#[test]
fn malformed_policy_requests_are_rejected_as_a_whole() {
    let f = Fixture::new();
    let original = f.bytes("spd4");
    let (p, _) = at(&original, 18);
    let r = p + 16;
    for length in [0, 5, 7, 16, 24, 48] {
        let mut b = original.clone();
        ne16(&mut b, r, length);
        rejected(&b, "request byte length");
    }
    for (offset, value) in [(4, 0), (4, 1), (5, 4)] {
        let mut b = original.clone();
        b[r + offset] = value;
        rejected(&b, "request attributes");
    }
    let mut b = original.clone();
    ne16(&mut b, r + 2, 0);
    rejected(&b, "request protocol");
    for (offset, value) in [(4, 6), (4, 1), (6, 4)] {
        let mut b = original.clone();
        b[p + offset] = value;
        rejected(&b, "policy attributes");
    }
    let mut b = f.bytes("none");
    let (p, _) = at(&b, 18);
    ne16(&mut b, p + 4, 6);
    rejected(&b, "unknown policy without requests");
    let mut b = f.bytes("wildcard");
    let (p, _) = at(&b, 18);
    b[p + 16 + 4] = 0;
    rejected(&b, "unknown request mode without addresses");
    let mut b = original.clone();
    b[r + 8] = 0;
    rejected(&b, "request endpoint size");
    let (base, n) = at(&original, 18);
    let mut ext = original[base..base + n].to_vec();
    ext.extend_from_slice(&[0; 8]);
    rejected(&replace(&original, 18, ext), "request trailing bytes");
}

// Mutations: discard unrecognized extension types, truncate request chains, or
// remove the per-packet extension/request bounds. These remain observations.
#[test]
fn unknown_metadata_is_marked_and_limits_do_not_drop_a_valid_prefix() {
    let f = Fixture::new();
    let original = f.bytes("sa4");
    let mut b = original.clone();
    for k in 1000u16..1058 {
        let mut ext = [0; 8];
        ne16(&mut ext, 0, 1);
        ne16(&mut ext, 2, k);
        b.extend(ext);
    }
    let b = finish(b);
    let Entry::Sa(s) = decode(&b).unwrap().entry else {
        panic!("SA")
    };
    assert_eq!(s.extra_extensions, (1000..1058).collect());
    let mut b = b;
    let mut ext = [0; 8];
    ne16(&mut ext, 0, 1);
    ne16(&mut ext, 2, 1058);
    b.extend(ext);
    rejected(&finish(b), "extension bound");
    let original = f.bytes("wildcard");
    let (p, n) = at(&original, 18);
    let request = &original[p + 16..p + n];
    assert_eq!(request.len(), 8);
    let mut ext = original[p..p + 16].to_vec();
    for _ in 0..64 {
        ext.extend(request);
    }
    let b = replace(&original, 18, ext.clone());
    let Entry::Policy(s) = decode(&b).unwrap().entry else {
        panic!("SPD")
    };
    assert_eq!(s.requests.len(), 64);
    ext.extend(request);
    rejected(&replace(&original, 18, ext), "request bound");
}
