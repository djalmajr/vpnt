use super::{backend::Backend, icon, placement};
use crate::bridge::{Command, Request};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

#[test]
fn lua_targets_only_valid_lowercase_hex_addresses() {
    let frame = placement::Frame {
        x: -12,
        y: 26,
        height: 300,
    };
    assert_eq!(
        placement::lua_for_frame("0x12ab", &frame).as_deref(),
        Some(concat!(
            "hl.dispatch(hl.dsp.window.float({ action = \"on\", window = \"address:0x12ab\" })); ",
            "hl.dispatch(hl.dsp.window.resize({ x = 320, y = 300, relative = false, window = \"address:0x12ab\" })); ",
            "hl.dispatch(hl.dsp.window.move({ x = -12, y = 26, relative = false, window = \"address:0x12ab\" }))"
        ))
    );
    for invalid in [
        "0x12;os.exit()",
        "12",
        "",
        "0x",
        "0x1A",
        "0x1\"})",
        "0x12\n",
    ] {
        assert!(
            placement::lua_for_frame(invalid, &frame).is_none(),
            "{invalid:?}"
        );
    }
}

#[test]
fn eval_accepts_only_ok_with_whitespace() {
    assert!(placement::eval_response(" \nok \t").is_ok());
    for response in ["", "error: bad", "ok\nerror: bad", "okay"] {
        assert!(placement::eval_response(response).is_err(), "{response:?}");
    }
}

#[test]
fn generation_invalidates_older_open_and_hidden_panel() {
    let generation = placement::Generation::default();
    let first = placement::advance(&generation);
    // Interleave a new opening after the worker's earlier generation check.
    assert!(placement::is_current(&generation, first));
    let second = placement::advance(&generation);
    let mut effects = Vec::new();
    placement::dispatch_if_current(&generation, first, || {
        effects.push("first");
        Ok(())
    })
    .unwrap();
    placement::dispatch_if_current(&generation, second, || {
        effects.push("second");
        Ok(())
    })
    .unwrap();
    assert_eq!(effects, ["second"]);
    assert!(placement::is_current(&generation, second));
    // Hiding between the earlier read and the effect invalidates that opening.
    placement::advance(&generation);
    placement::dispatch_if_current(&generation, second, || {
        effects.push("hidden");
        Ok(())
    })
    .unwrap();
    assert_eq!(effects, ["second"]);
    assert!(!placement::is_current(&generation, first));
    assert!(!placement::is_current(&generation, second));
}

#[test]
fn stale_dispatch_is_rejected_when_open_or_hide_interleaves() {
    for reopen in [true, false] {
        let generation = placement::Generation::default();
        let first = placement::advance(&generation);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let (effect_tx, effect_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let generation_ref = &generation;
            let worker_effect_tx = effect_tx.clone();
            let worker = scope.spawn(move || {
                let _ = ready_tx.send(placement::is_current(generation_ref, first));
                let _ = resume_rx.recv_timeout(Duration::from_secs(2));
                placement::dispatch_if_current(generation_ref, first, || {
                    let _ = worker_effect_tx.send("stale");
                    Ok(())
                })
                .unwrap();
            });
            assert!(ready_rx.recv_timeout(Duration::from_secs(2)).unwrap());
            let next = placement::advance(&generation);
            resume_tx.send(()).unwrap();
            worker.join().unwrap();
            if reopen {
                placement::dispatch_if_current(&generation, next, || {
                    let _ = effect_tx.send("current");
                    Ok(())
                })
                .unwrap();
            }
        });
        drop(effect_tx);
        let effects: Vec<_> = effect_rx.into_iter().collect();
        assert_eq!(effects, if reopen { vec!["current"] } else { vec![] });
    }
}

#[test]
fn focus_hide_suppresses_only_recent_clicks() {
    let hidden = Instant::now();
    assert!(!super::suppress_click(None, hidden));
    assert!(super::suppress_click(
        Some(hidden),
        hidden + Duration::from_millis(120)
    ));
    assert!(super::suppress_click(
        Some(hidden),
        hidden + Duration::from_millis(400)
    ));
    assert!(!super::suppress_click(
        Some(hidden),
        hidden + Duration::from_millis(401)
    ));
    assert!(!super::suppress_click(
        Some(hidden),
        hidden + Duration::from_secs(2)
    ));
}

fn request(command: Command) -> Request {
    Request {
        id: "test-1".into(),
        command,
        locale: None,
    }
}

fn monitors(json: &str) -> Vec<placement::Monitor> {
    placement::parse_monitors(json).unwrap()
}

#[test]
fn geometry_corners_scaled_and_second_monitor() {
    let m =
        monitors(r#"[{"x":0,"y":0,"width":2560,"height":1440,"scale":1,"reserved":[0,26,0,0]}]"#);
    let right = placement::frame(placement::Anchor { x: 2400.0, y: 10.0 }, &m, 360).unwrap();
    assert_eq!(
        right,
        placement::Frame {
            x: 2232,
            y: 26,
            height: 360
        }
    );
    let left = placement::frame(placement::Anchor { x: 100.0, y: 10.0 }, &m, 360).unwrap();
    assert_eq!(left.x, 8);
    let scaled =
        monitors(r#"[{"x":0,"y":0,"width":2880,"height":1800,"scale":1.5,"reserved":[0,30,0,0]}]"#);
    assert_eq!(
        placement::frame(placement::Anchor { x: 1900.0, y: 5.0 }, &scaled, 900).unwrap(),
        placement::Frame {
            x: 1592,
            y: 30,
            height: 720
        }
    );
    let two = monitors(
        r#"[{"x":0,"y":0,"width":1920,"height":1080,"scale":1,"reserved":[0,26,0,0]},{"x":1920,"y":0,"width":2560,"height":1440,"scale":1,"reserved":[0,26,0,0]}]"#,
    );
    let second = placement::frame(placement::Anchor { x: 2000.0, y: 10.0 }, &two, 360).unwrap();
    assert_eq!(
        second,
        placement::Frame {
            x: 1928,
            y: 26,
            height: 360
        }
    );
    let bottom = placement::frame(
        placement::Anchor {
            x: 3000.0,
            y: 1300.0,
        },
        &two,
        900,
    )
    .unwrap();
    assert_eq!(bottom.y, 720);
    assert_eq!(bottom.height, 720);
}

#[test]
fn parse_hyprland_responses_and_reject_malformed() {
    let anchor = placement::parse_anchor(r#"{"x":-120,"y":42}"#).unwrap();
    assert_eq!((anchor.x, anchor.y), (-120.0, 42.0));
    assert!(placement::parse_anchor(r#"{"x":"oops","y":42}"#).is_err());
    let data = r#"[{"x":0,"y":0,"width":2560,"height":1600,"scale":1.6,"reserved":[0,26,0,0]}]"#;
    assert_eq!(monitors(data).len(), 1);
    assert!(placement::parse_monitors(r#"[{"x":0}]"#).is_err());
    let clients = placement::parse_clients(
        r#"[{"pid":123,"title":"VPN Tray","address":"0xabcd","floating":true,"pinned":false}]"#,
    )
    .unwrap();
    assert_eq!(
        (
            clients[0].pid,
            clients[0].title.as_str(),
            clients[0].address.as_str(),
            clients[0].floating,
            clients[0].pinned
        ),
        (123, "VPN Tray", "0xabcd", true, false)
    );
    assert!(placement::parse_clients(r#"[{"pid":123,"title":"VPN Tray"}]"#).is_err());
}

#[test]
fn icon_is_rgba_with_transparent_corners_and_opaque_white() {
    let pixels = icon::open_lock_rgba();
    assert_eq!(pixels.len(), 4096);
    for (x, y) in [(0, 0), (31, 0), (0, 31), (31, 31)] {
        assert_eq!(pixels[(y * 32 + x) * 4 + 3], 0);
    }
    let chunks = pixels.as_chunks::<4>().0;
    assert!(chunks.contains(&[255, 255, 255, 255]));
    assert!(
        chunks
            .iter()
            .all(|p| p[3] == 0 || *p == [255, 255, 255, 255])
    );
    assert!(icon::open_lock().is_ok());
}

#[test]
fn backend_demo_and_normal_contract() {
    for demo in [true, false] {
        let (tx, rx) = mpsc::channel();
        let backend = Backend::new(demo, move |reply| {
            let _ = tx.send(reply);
        })
        .unwrap();
        backend
            .send(request(Command::GetSnapshot {}), Instant::now())
            .unwrap();
        let reply = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(reply.id, "test-1");
        let snapshot = reply.snapshot.unwrap();
        assert_eq!(snapshot.demo, demo);
        assert_eq!(snapshot.vpns.len(), if demo { 2 } else { 0 });
        if !demo {
            backend
                .send(request(Command::Connect { id: "x".into() }), Instant::now())
                .unwrap();
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .error
                    .as_deref(),
                Some("not_implemented")
            );
        }
    }
}

#[test]
fn backend_rejects_full_queue() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let backend = Backend::new(true, move |_| {
        let _ = entered_tx.send(());
        let _ = release_rx.recv();
    })
    .unwrap();
    backend
        .send(request(Command::GetSnapshot {}), Instant::now())
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let results: Vec<_> = (0..33)
        .map(|_| backend.send(request(Command::GetSnapshot {}), Instant::now()))
        .collect();
    drop(release_tx);
    assert!(results[..32].iter().all(Result::is_ok));
    assert_eq!(results[32], Err(()));
}

#[test]
fn backend_rejects_dead_thread() {
    let (tx, rx) = mpsc::channel();
    let backend = Backend::new(true, move |_| {
        let _ = tx.send(());
        panic!("stop backend");
    })
    .unwrap();
    backend
        .send(request(Command::GetSnapshot {}), Instant::now())
        .unwrap();
    rx.recv_timeout(Duration::from_secs(2)).unwrap();
    // Fewer than 32 attempts distinguish a disconnected receiver from a full queue.
    for _ in 0..20 {
        if backend
            .send(request(Command::GetSnapshot {}), Instant::now())
            .is_err()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("backend thread did not terminate");
}
