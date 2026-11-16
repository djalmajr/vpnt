use serde::Deserialize;
use std::{
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    time::{Duration, Instant},
};

use super::PRODUCT_NAME;

const HYPRCTL: &str = "/usr/bin/hyprctl";
const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
pub(super) struct Anchor {
    pub(super) x: f64,
    pub(super) y: f64,
}

#[derive(Debug, Deserialize)]
pub(super) struct Monitor {
    #[serde(default)]
    name: String,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    scale: f64,
    reserved: [f64; 4],
}

#[derive(Debug, PartialEq)]
pub(super) struct Frame {
    pub(super) x: i32,
    pub(super) y: i32,
    pub(super) height: u32,
}

#[derive(Deserialize)]
pub(super) struct Client {
    pub(super) address: String,
    pub(super) pid: u32,
    pub(super) title: String,
    pub(super) floating: bool,
    pub(super) pinned: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct PlacementRequest {
    pub(super) generation: u64,
    opening: u64,
    pub(super) is_opening: bool,
    pub(super) anchor: Option<Anchor>,
    pub(super) requested: u32,
}

pub(super) fn click_request(
    generation: u64,
    anchor: Option<Anchor>,
    requested: u32,
) -> PlacementRequest {
    PlacementRequest {
        generation,
        opening: generation,
        is_opening: true,
        anchor,
        requested,
    }
}

pub(super) fn resize_request(
    generation: u64,
    opening: u64,
    anchor: Option<Anchor>,
    requested: u32,
) -> PlacementRequest {
    PlacementRequest {
        generation,
        opening,
        is_opening: false,
        anchor,
        requested,
    }
}

pub(super) fn applied_height(current: u64, received: u64, height: u32) -> Option<u32> {
    (current == received).then_some(height)
}

fn hyprland() -> bool {
    std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some()
}

// Both pipes are drained while the child runs, so a full pipe cannot defeat the deadline.
pub(super) fn command_at(path: &Path, args: &[&str]) -> Result<String, String> {
    let deadline = Instant::now() + TIMEOUT;
    let mut child = Command::new(path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let stdout = child.stdout.take().ok_or("Missing stdout")?;
    let stderr = child.stderr.take().ok_or("Missing stderr")?;
    let (tx, rx) = mpsc::channel();
    let out_tx = tx.clone();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(8 * 1024 * 1024).read_to_end(&mut bytes);
        let _ = out_tx.send((true, result.map(|_| bytes)));
    });
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stderr.take(8 * 1024 * 1024).read_to_end(&mut bytes);
        let _ = tx.send((false, result.map(|_| bytes)));
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("hyprctl timed out after 2s".into());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
    };
    let mut out = None;
    let mut err = None;
    for _ in 0..2 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (is_stdout, bytes) = rx
            .recv_timeout(remaining)
            .map_err(|_| "hyprctl timed out after 2s")?;
        let bytes = bytes.map_err(|e| e.to_string())?;
        if is_stdout {
            out = Some(bytes);
        } else {
            err = Some(bytes);
        }
    }
    let stdout = out.unwrap_or_default();
    if !status.success() {
        let stderr = err.unwrap_or_default();
        return Err(
            String::from_utf8_lossy(if stderr.is_empty() { &stdout } else { &stderr }).into_owned(),
        );
    }
    String::from_utf8(stdout).map_err(|error| error.to_string())
}

fn command(args: &[&str]) -> Result<String, String> {
    command_at(Path::new(HYPRCTL), args)
}

pub(super) fn parse_anchor(json: &str) -> Result<Anchor, serde_json::Error> {
    serde_json::from_str(json)
}

pub(super) fn parse_monitors(json: &str) -> Result<Vec<Monitor>, serde_json::Error> {
    serde_json::from_str(json)
}

pub(super) fn parse_clients(json: &str) -> Result<Vec<Client>, serde_json::Error> {
    serde_json::from_str(json)
}

pub(super) fn capture() -> Option<Anchor> {
    if !hyprland() {
        return None;
    }
    match command(&["cursorpos", "-j"]).and_then(|s| parse_anchor(&s).map_err(|e| e.to_string())) {
        Ok(anchor) => Some(anchor),
        Err(error) => {
            eprintln!("Could not capture cursor position: {error}");
            None
        }
    }
}

fn monitor_for_anchor(anchor: Anchor, monitors: &[Monitor]) -> Option<&Monitor> {
    monitors
        .iter()
        .find(|m| {
            m.scale > 0.0
                && anchor.x >= m.x
                && anchor.x < m.x + m.width / m.scale
                && anchor.y >= m.y
                && anchor.y < m.y + m.height / m.scale
        })
        .or_else(|| monitors.first())
}

pub(super) fn frame(anchor: Anchor, monitors: &[Monitor], requested: u32) -> Option<Frame> {
    let monitor = monitor_for_anchor(anchor, monitors)?;
    if monitor.scale <= 0.0 {
        return None;
    }
    let width = monitor.width / monitor.scale;
    let height = monitor.height / monitor.scale;
    let [left, top, right, bottom] = monitor.reserved;
    let available = (height - top - bottom - 24.0).max(0.0) as u32;
    let panel_height = requested.clamp(180, 720).min(available);
    let min_x = monitor.x + left + 8.0;
    let max_x = (monitor.x + width - right - 8.0 - 320.0).max(min_x);
    let x = (anchor.x - 160.0).clamp(min_x, max_x);
    let y = if anchor.y < monitor.y + height / 2.0 {
        monitor.y + top
    } else {
        monitor.y + height - bottom - f64::from(panel_height)
    };
    Some(Frame {
        x: x.round() as i32,
        y: y.round() as i32,
        height: panel_height,
    })
}

#[derive(Default)]
pub(super) struct Generation {
    value: AtomicU64,
}

pub(super) fn advance(generation: &Generation) -> u64 {
    generation
        .value
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1)
}

pub(super) fn current(generation: &Generation) -> u64 {
    generation.value.load(Ordering::SeqCst)
}

pub(super) fn is_current(generation: &Generation, expected: u64) -> bool {
    current(generation) == expected
}

pub(super) fn dispatch_if_current(
    generation: &Generation,
    expected: u64,
    dispatch: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if is_current(generation, expected) {
        dispatch()
    } else {
        Ok(())
    }
}

pub(super) fn eval_response(response: &str) -> Result<(), String> {
    if response.trim() == "ok" {
        Ok(())
    } else {
        Err(response.to_owned())
    }
}

fn eval(lua: &str) -> Result<(), String> {
    eval_response(&command(&["eval", lua])?)
}

pub(super) const PREPARE_RULE: &str = concat!(
    r#"if o and o.window then o.window({ class = "^(vpnt)$", title = "^(VPN Tray)$" }, "#,
    r#"{ name = "vpnt-tray", float = true, pin = true }) else "#,
    r#"hl.window_rule({ name = "vpnt-tray", match = { class = "^(vpnt)$", title = "^(VPN Tray)$" }, float = true, pin = true }) end"#,
);

fn prepare() -> Result<(), String> {
    eval(PREPARE_RULE)
}

pub(super) fn lua_opening_rule(monitor: &Monitor, frame: &Frame) -> String {
    let location = if !monitor.name.is_empty()
        && monitor
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        format!(
            ", monitor = \"{}\", size = {{ 320, {} }}, move = {{ {}, {} }}",
            monitor.name,
            frame.height,
            (f64::from(frame.x) - monitor.x).round() as i64,
            (f64::from(frame.y) - monitor.y).round() as i64,
        )
    } else {
        format!(", size = {{ 320, {} }}", frame.height)
    };
    format!(
        r#"hl.window_rule({{ name = "vpnt-tray", match = {{ class = "^(vpnt)$", title = "^(VPN Tray)$" }}, float = true, pin = true{location}, animation = "popin 100%" }})"#
    )
}

pub(super) fn lua_for_frame(address: &str, frame: &Frame) -> Option<String> {
    let hex = address.strip_prefix("0x")?;
    if hex.is_empty()
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let target = format!("address:{address}");
    Some(format!(
        "hl.dispatch(hl.dsp.window.float({{ action = \"on\", window = \"{target}\" }})); \
         hl.dispatch(hl.dsp.window.resize({{ x = 320, y = {}, relative = false, window = \"{target}\" }})); \
         hl.dispatch(hl.dsp.window.move({{ x = {}, y = {}, relative = false, window = \"{target}\" }}))",
        frame.height, frame.x, frame.y
    ))
}

pub(super) struct Positioner {
    input: Sender<PlacementRequest>,
    supported: bool,
}

impl Positioner {
    pub(super) fn new(
        generation: Arc<Generation>,
        reply: impl Fn(u64, u32, Option<Anchor>, bool) + Send + 'static,
    ) -> std::io::Result<Self> {
        let supported = hyprland() && Path::new(HYPRCTL).is_file();
        let (input, requests) = mpsc::channel();
        std::thread::Builder::new()
            .name("vpnt-desktop-placement".into())
            .spawn(move || {
                let ready = if supported {
                    match prepare() {
                        Ok(()) => true,
                        Err(error) => {
                            eprintln!("Could not register popover rule: {error}");
                            false
                        }
                    }
                } else {
                    false
                };
                worker_loop(
                    requests,
                    &generation,
                    || if ready { capture() } else { None },
                    |request| {
                        if ready {
                            apply(request, &generation)
                        } else {
                            Ok(None)
                        }
                    },
                    reply,
                );
            })?;
        Ok(Self { input, supported })
    }

    pub(super) fn supported(&self) -> bool {
        self.supported
    }

    pub(super) fn send(&self, request: PlacementRequest) -> Result<(), ()> {
        self.input.send(request).map_err(|_| ())
    }
}

pub(super) fn worker_loop(
    requests: Receiver<PlacementRequest>,
    generation: &Generation,
    mut capture_anchor: impl FnMut() -> Option<Anchor>,
    mut process: impl FnMut(PlacementRequest) -> Result<Option<u32>, String>,
    reply: impl Fn(u64, u32, Option<Anchor>, bool),
) {
    let mut opening_anchor: Option<(u64, Anchor)> = None;
    while let Ok(mut request) = requests.recv() {
        while let Ok(latest) = requests.try_recv() {
            request = latest;
        }
        if !is_current(generation, request.generation) {
            continue;
        }
        if request.anchor.is_none() {
            request.anchor = opening_anchor
                .filter(|(opening, _)| *opening == request.opening)
                .map(|(_, anchor)| anchor)
                .or_else(&mut capture_anchor);
        }
        if let Some(anchor) = request.anchor {
            opening_anchor = Some((request.opening, anchor));
        }
        let height = match process(request) {
            Ok(Some(height)) => height,
            Ok(None) => request.requested.clamp(180, 720),
            Err(error) => {
                eprintln!("Could not place popover: {error}");
                request.requested.clamp(180, 720)
            }
        };
        if is_current(generation, request.generation) {
            reply(
                request.generation,
                height,
                request.anchor,
                request.is_opening,
            );
        }
    }
}

fn own_client() -> Result<Option<Client>, String> {
    let clients = parse_clients(&command(&["clients", "-j"])?).map_err(|e| e.to_string())?;
    Ok(clients
        .into_iter()
        .find(|c| c.pid == std::process::id() && c.title == PRODUCT_NAME))
}

fn apply(request: PlacementRequest, generation: &Generation) -> Result<Option<u32>, String> {
    let Some(anchor) = request.anchor else {
        return Ok(None);
    };
    let monitors = parse_monitors(&command(&["monitors", "-j"])?).map_err(|e| e.to_string())?;
    let frame = frame(anchor, &monitors, request.requested).ok_or("No valid monitor")?;
    if request.is_opening {
        let monitor = monitor_for_anchor(anchor, &monitors).ok_or("No valid monitor")?;
        let rule = lua_opening_rule(monitor, &frame);
        dispatch_if_current(generation, request.generation, || {
            if let Err(error) = eval(&rule) {
                eprintln!("Could not register popover animation rule: {error}");
                let fallback = rule.replace(", animation = \"popin 100%\"", "");
                eval(&fallback)?;
            }
            Ok(())
        })?;
        return Ok(Some(frame.height));
    }
    for attempt in 0..25 {
        if !is_current(generation, request.generation) {
            return Ok(None);
        }
        if own_client()?.is_some() {
            std::thread::sleep(Duration::from_millis(20));
            if !is_current(generation, request.generation) {
                return Ok(None);
            }
            if let Some(client) = own_client()? {
                let lua = lua_for_frame(&client.address, &frame).ok_or("Invalid client address")?;
                if !client.pinned {
                    eprintln!("Popover is not pinned (floating: {})", client.floating);
                }
                dispatch_if_current(generation, request.generation, || eval(&lua))?;
                return Ok(Some(frame.height));
            }
        }
        if attempt < 24 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    Err("Window not found after 25 attempts".into())
}
