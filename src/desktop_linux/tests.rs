use super::{backend::Backend, icon, placement};
use crate::bridge::{Command, Request};
use std::{
    sync::{Arc, mpsc},
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
fn timeout_kills_and_reaps_the_fake_executable() {
    use std::os::unix::fs::PermissionsExt;
    struct TempRoot(std::path::PathBuf);
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!(
        "vpnt-placement-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir(&path).unwrap();
    let root = TempRoot(path);
    let script = root.0.join("fake hyprctl");
    let pid_file = root.0.join("pid file");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf '%s' \"$$\" > \"$1\"\nexec /usr/bin/sleep 5\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let start = Instant::now();
    let result = placement::command_at(&script, &[pid_file.to_str().unwrap()]);
    let elapsed = start.elapsed();
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    let still_exists = std::path::Path::new("/proc").join(pid.trim()).exists();
    assert_eq!(result.unwrap_err(), "hyprctl timed out after 2s");
    assert!(
        elapsed <= Duration::from_millis(2500),
        "elapsed={elapsed:?} script={script:?}"
    );
    assert!(!still_exists, "child PID {pid} still exists after timeout");
}

#[test]
fn generation_advance_does_not_wait_for_retained_dispatch() {
    let generation = Arc::new(placement::Generation::default());
    let first = placement::advance(&generation);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker_generation = Arc::clone(&generation);
    let worker = std::thread::spawn(move || {
        placement::dispatch_if_current(&worker_generation, first, || {
            let _ = entered_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
            Ok(())
        })
        .unwrap();
    });
    let entered = entered_rx.recv_timeout(Duration::from_secs(2));
    let (done_tx, done_rx) = mpsc::channel();
    let advancing_generation = Arc::clone(&generation);
    let advancing = std::thread::spawn(move || {
        let next = placement::advance(&advancing_generation);
        let _ = done_tx.send(next);
    });
    let advanced_before_release = done_rx.recv_timeout(Duration::from_millis(250));
    let _ = release_tx.send(());
    worker.join().unwrap();
    advancing.join().unwrap();
    assert!(entered.is_ok());
    assert_eq!(advanced_before_release.unwrap(), first + 1);
}

#[test]
fn worker_discards_stale_work_and_coalesces_requests() {
    let generation = Arc::new(placement::Generation::default());
    let (input, requests) = mpsc::channel();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (processed_tx, processed_rx) = mpsc::channel();
    let (effect_tx, effect_rx) = mpsc::channel();
    let (reply_tx, reply_rx) = mpsc::channel();
    let worker_generation = Arc::clone(&generation);
    let worker = std::thread::spawn(move || {
        placement::worker_loop(
            requests,
            &worker_generation,
            || None,
            |request| {
                let _ = processed_tx.send(request.generation);
                if request.generation == 1 {
                    let _ = entered_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(2));
                }
                placement::dispatch_if_current(&worker_generation, request.generation, || {
                    let _ = effect_tx.send(request.generation);
                    Ok(())
                })?;
                Ok(Some(request.requested))
            },
            |generation, height, _, _| {
                let _ = reply_tx.send((generation, height));
            },
        );
    });
    let first = placement::advance(&generation);
    input
        .send(placement::click_request(first, None, 200))
        .unwrap();
    let entered = entered_rx.recv_timeout(Duration::from_secs(2));
    let second = placement::advance(&generation);
    input
        .send(placement::click_request(second, None, 300))
        .unwrap();
    let third = placement::advance(&generation);
    input
        .send(placement::click_request(third, None, 400))
        .unwrap();
    let _ = release_tx.send(());
    drop(input);
    worker.join().unwrap();
    assert!(entered.is_ok());
    assert_eq!(processed_rx.into_iter().collect::<Vec<_>>(), [first, third]);
    assert_eq!(effect_rx.into_iter().collect::<Vec<_>>(), [third]);
    assert_eq!(reply_rx.into_iter().collect::<Vec<_>>(), [(third, 400)]);
}

#[test]
fn applied_height_discards_stale_and_uses_short_monitor() {
    let monitors =
        monitors(r#"[{"x":0,"y":0,"width":1280,"height":600,"scale":1,"reserved":[0,26,0,0]}]"#);
    let frame = placement::frame(placement::Anchor { x: 600.0, y: 10.0 }, &monitors, 720).unwrap();
    assert_eq!(frame.height, 550);
    let generation = placement::Generation::default();
    let current = placement::advance(&generation);
    let (input, requests) = mpsc::channel();
    let (reply_tx, reply_rx) = mpsc::channel();
    input
        .send(placement::click_request(
            current,
            Some(placement::Anchor { x: 600.0, y: 10.0 }),
            720,
        ))
        .unwrap();
    drop(input);
    placement::worker_loop(
        requests,
        &generation,
        || None,
        |request| {
            Ok(
                placement::frame(request.anchor.unwrap(), &monitors, request.requested)
                    .map(|f| f.height),
            )
        },
        |generation, height, _, _| {
            let _ = reply_tx.send((generation, height));
        },
    );
    let (placed, height) = reply_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!((placed, height), (current, 550));
    assert_eq!(placement::applied_height(current + 1, placed, height), None);
    assert_eq!(
        placement::applied_height(current, placed, height),
        Some(550)
    );
}

#[test]
fn show_resize_keeps_the_opening_anchor_after_cursor_moves() {
    use std::cell::Cell;
    let generation = placement::Generation::default();
    let monitors =
        monitors(r#"[{"x":0,"y":0,"width":1920,"height":1080,"scale":1,"reserved":[0,26,0,0]}]"#);
    let pointer = Cell::new(placement::Anchor { x: 100.0, y: 10.0 });
    let captures = Cell::new(0);
    let moves = std::cell::RefCell::new(Vec::new());
    let mut stored_anchor = None;
    let mut opening = 0;
    for height in [360, 500] {
        let current = placement::advance(&generation);
        let (tx, rx) = mpsc::channel();
        let request = if opening == 0 {
            opening = current;
            placement::click_request(current, None, height)
        } else {
            placement::resize_request(current, opening, stored_anchor, height)
        };
        tx.send(request).unwrap();
        drop(tx);
        let (reply_tx, reply_rx) = mpsc::channel();
        placement::worker_loop(
            rx,
            &generation,
            || {
                captures.set(captures.get() + 1);
                Some(pointer.get())
            },
            |request| {
                let frame = placement::frame(request.anchor.unwrap(), &monitors, request.requested)
                    .unwrap();
                moves.borrow_mut().push((frame.x, frame.y));
                Ok(Some(frame.height))
            },
            |generation, height, anchor, _| {
                let _ = reply_tx.send((generation, height, anchor));
            },
        );
        let (placed, height, anchor) = reply_rx.recv().unwrap();
        assert_eq!(
            super::accept_placement(current, placed, height, &mut stored_anchor, anchor),
            Some(height)
        );
        assert_eq!(stored_anchor, Some(placement::Anchor { x: 100.0, y: 10.0 }));
        pointer.set(placement::Anchor { x: 250.0, y: 10.0 });
    }
    assert_eq!(*moves.borrow(), [(8, 26), (8, 26)]);
    assert_eq!(captures.get(), 1);
}

#[test]
fn placed_anchor_ignores_stale_events_and_never_replaces_click_anchor() {
    let first = Some(placement::Anchor { x: 100.0, y: 10.0 });
    let second = Some(placement::Anchor { x: 250.0, y: 10.0 });
    let mut saved = None;
    assert_eq!(super::accept_placement(2, 1, 360, &mut saved, first), None);
    assert_eq!(saved, None);
    assert_eq!(
        super::accept_placement(2, 2, 360, &mut saved, first),
        Some(360)
    );
    assert_eq!(saved, first);
    assert_eq!(
        super::accept_placement(2, 2, 400, &mut saved, second),
        Some(400)
    );
    assert_eq!(saved, first);
    saved = second;
    assert_eq!(super::accept_placement(3, 2, 360, &mut saved, first), None);
    assert_eq!(saved, second);
    assert_eq!(
        super::accept_placement(3, 3, 360, &mut saved, first),
        Some(360)
    );
    assert_eq!(saved, second);
}

#[test]
fn resize_before_first_placed_reuses_capture_but_new_opening_recaptures() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let generation = Arc::new(placement::Generation::default());
    let count = Arc::new(AtomicUsize::new(0));
    let (input, requests) = mpsc::channel();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (moves_tx, moves_rx) = mpsc::channel();
    let (reply_tx, reply_rx) = mpsc::channel();
    let worker_gen = Arc::clone(&generation);
    let worker_count = Arc::clone(&count);
    let first = placement::advance(&generation);
    let worker = std::thread::spawn(move || {
        let screens = monitors(
            r#"[{"x":0,"y":0,"width":1920,"height":1080,"scale":1,"reserved":[0,26,0,0]}]"#,
        );
        placement::worker_loop(
            requests,
            &worker_gen,
            || {
                let n = worker_count.fetch_add(1, Ordering::SeqCst);
                Some(placement::Anchor {
                    x: if n == 0 { 100.0 } else { 250.0 },
                    y: 10.0,
                })
            },
            |req| {
                let frame = placement::frame(req.anchor.unwrap(), &screens, req.requested).unwrap();
                if req.generation == first {
                    let _ = entered_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(2));
                }
                placement::dispatch_if_current(&worker_gen, req.generation, || {
                    let _ = moves_tx.send((frame.x, frame.y));
                    Ok(())
                })?;
                Ok(Some(frame.height))
            },
            |generation, height, anchor, _| {
                let _ = reply_tx.send((generation, height, anchor));
            },
        );
    });
    input
        .send(placement::click_request(first, None, 360))
        .unwrap();
    let entered = entered_rx.recv_timeout(Duration::from_secs(2));
    let second = placement::advance(&generation);
    input
        .send(placement::resize_request(second, first, None, 500))
        .unwrap();
    let _ = release_tx.send(());
    let resized = reply_rx.recv_timeout(Duration::from_secs(2));
    let third = placement::advance(&generation);
    input
        .send(placement::click_request(third, None, 360))
        .unwrap();
    let reopened = reply_rx.recv_timeout(Duration::from_secs(2));
    drop(input);
    worker.join().unwrap();
    assert!(entered.is_ok());
    assert_eq!(
        resized.unwrap(),
        (second, 500, Some(placement::Anchor { x: 100.0, y: 10.0 }))
    );
    assert_eq!(
        reopened.unwrap(),
        (third, 360, Some(placement::Anchor { x: 250.0, y: 10.0 }))
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(
        moves_rx.into_iter().collect::<Vec<_>>(),
        [(8, 26), (90, 26)]
    );
}

#[test]
fn each_open_request_uses_its_click_anchor() {
    let first = Some(placement::Anchor { x: 100.0, y: 10.0 });
    let second = Some(placement::Anchor { x: 2000.0, y: 20.0 });
    let one = placement::click_request(1, first, 360);
    let two = placement::click_request(2, second, 360);
    assert_eq!(one.anchor, first);
    assert_eq!(two.anchor, second);
    assert_ne!(one.anchor, two.anchor);
    assert_eq!((one.generation, two.generation), (1, 2));
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

#[test]
fn show_and_deadline_decisions_respect_visibility_and_generation() {
    use super::{ShowDecision, show_decision};
    assert_eq!(
        show_decision(true, false, false, true),
        ShowDecision::Ignore
    );
    assert_eq!(
        show_decision(false, false, true, true),
        ShowDecision::Ignore
    );
    assert_eq!(show_decision(true, false, true, true), ShowDecision::Show);
    assert_eq!(
        show_decision(true, false, true, false),
        ShowDecision::Ignore
    );
    assert_eq!(
        show_decision(true, true, true, true),
        ShowDecision::Reposition
    );
}

#[test]
fn opening_rule_uses_monitor_local_coordinates_and_rejects_invalid_names() {
    let cases = [
        ("HDMI-A-1", 1600, 3267.0, 3107, 1507),
        ("eDP-2", 0, 100.0, 8, 8),
    ];
    for (name, origin, anchor_x, global_x, local_x) in cases {
        let monitors = monitors(&format!(
            r#"[{{"name":"{name}","x":{origin},"y":0,"width":1920,"height":1080,"scale":1,"reserved":[0,26,0,0]}}]"#
        ));
        let frame = placement::frame(
            placement::Anchor {
                x: anchor_x,
                y: 10.0,
            },
            &monitors,
            360,
        )
        .unwrap();
        assert_eq!(frame.x, global_x);
        assert_eq!(
            placement::lua_opening_rule(&monitors[0], &frame),
            format!(
                r#"hl.window_rule({{ name = "vpnt-tray", match = {{ class = "^(vpnt)$", title = "^(VPN Tray)$" }}, float = true, pin = true, monitor = "{name}", size = {{ 320, 360 }}, move = {{ {local_x}, 26 }}, animation = "popin 100%" }})"#
            )
        );
    }
    for name in ["DP-1\"", "a b", "", "DP\n1", "éDP", "a;b"] {
        let json = serde_json::json!([{ "name": name, "x": 0, "y": 0, "width": 1920, "height": 1080, "scale": 1, "reserved": [0, 26, 0, 0] }]);
        let monitors = monitors(&json.to_string());
        let frame =
            placement::frame(placement::Anchor { x: 100.0, y: 10.0 }, &monitors, 360).unwrap();
        assert_eq!(
            placement::lua_opening_rule(&monitors[0], &frame),
            r#"hl.window_rule({ name = "vpnt-tray", match = { class = "^(vpnt)$", title = "^(VPN Tray)$" }, float = true, pin = true, size = { 320, 360 }, animation = "popin 100%" })"#,
            "{name:?}"
        );
    }
}

#[test]
fn prepare_rule_registers_with_omarchy_or_falls_back_to_hyprland() {
    assert_eq!(
        placement::PREPARE_RULE,
        r#"if o and o.window then o.window({ class = "^(vpnt)$", title = "^(VPN Tray)$" }, { name = "vpnt-tray", float = true, pin = true }) else hl.window_rule({ name = "vpnt-tray", match = { class = "^(vpnt)$", title = "^(VPN Tray)$" }, float = true, pin = true }) end"#
    );
}

#[test]
fn omarchy_gap_and_frame_examples() {
    assert_eq!(placement::parse_gap(r#"{"css":"10 10 10 10"}"#), 5);
    assert_eq!(placement::parse_gap(r#"{"int":7}"#), 4);
    assert_eq!(placement::parse_gap("bad"), 5);
    let screens = monitors(
        r#"[{"x":1600,"y":0,"width":3225,"height":1800,"scale":1,"reserved":[0,26,0,0]}]"#,
    );
    assert_eq!(
        placement::frame_with_gap(
            placement::Anchor {
                x: 3267.0,
                y: 278.0
            },
            &screens,
            480,
            Some(5)
        ),
        Some(placement::Frame {
            x: 3107,
            y: 31,
            height: 480
        })
    );
    assert_eq!(
        placement::frame_with_gap(
            placement::Anchor { x: 1650.0, y: 10.0 },
            &screens,
            480,
            Some(5)
        )
        .unwrap()
        .x,
        1605
    );
}

#[test]
fn initial_height_matches_design_contract() {
    assert_eq!(super::DEFAULT_HEIGHT, 480);
}
