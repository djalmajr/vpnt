use serde::Deserialize;
use std::{
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tao::{dpi::LogicalSize, window::Window};

use super::PRODUCT_NAME;

#[derive(Clone, Copy, Debug, Deserialize)]
pub(super) struct Anchor {
    pub(super) x: f64,
    pub(super) y: f64,
}

#[derive(Debug, Deserialize)]
pub(super) struct Monitor {
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

fn hyprland() -> bool {
    std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some()
}

fn command(args: &[&str]) -> Result<String, String> {
    let output = Command::new("/usr/bin/hyprctl")
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
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

pub(super) fn frame(anchor: Anchor, monitors: &[Monitor], requested: u32) -> Option<Frame> {
    let monitor = monitors
        .iter()
        .find(|m| {
            m.scale > 0.0
                && anchor.x >= m.x
                && anchor.x < m.x + m.width / m.scale
                && anchor.y >= m.y
                && anchor.y < m.y + m.height / m.scale
        })
        .or_else(|| monitors.first())?;
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
    gate: Mutex<()>,
}

pub(super) fn advance(generation: &Generation) -> u64 {
    let _guard = generation.gate.lock().unwrap_or_else(|e| e.into_inner());
    generation
        .value
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1)
}

pub(super) fn is_current(generation: &Generation, expected: u64) -> bool {
    generation.value.load(Ordering::SeqCst) == expected
}

pub(super) fn dispatch_if_current(
    generation: &Generation,
    expected: u64,
    dispatch: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let _guard = generation.gate.lock().unwrap_or_else(|e| e.into_inner());
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

pub(super) fn prepare() -> bool {
    if !hyprland() {
        return false;
    }
    let rule = r#"hl.window_rule({ name = "vpnt-tray", match = { class = "^(vpnt)$", title = "^(VPN Tray)$" }, float = true, pin = true })"#;
    match eval(rule) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("Could not register popover rule: {error}");
            false
        }
    }
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

pub(super) fn reposition(
    window: &Window,
    anchor: Option<Anchor>,
    requested: u32,
    generation: &Arc<Generation>,
    expected: u64,
) {
    if anchor.is_none() || !hyprland() || !std::path::Path::new("/usr/bin/hyprctl").is_file() {
        window.set_inner_size(LogicalSize::new(320, requested.clamp(180, 720)));
        return;
    }
    // GTK freezes the previous size when non-resizable; restore fixed bounds after resizing.
    window.set_min_inner_size(None::<LogicalSize<u32>>);
    window.set_max_inner_size(None::<LogicalSize<u32>>);
    window.set_resizable(true);
    window.set_inner_size(LogicalSize::new(320, requested.clamp(180, 720)));
    let Some(anchor) = anchor.filter(|_| hyprland()) else {
        return;
    };
    let generation = Arc::clone(generation);
    std::thread::spawn(move || {
        if let Err(error) = apply(anchor, requested, &generation, expected) {
            eprintln!("Could not place popover: {error}");
        }
    });
}

fn own_client() -> Result<Option<Client>, String> {
    let clients = parse_clients(&command(&["clients", "-j"])?).map_err(|e| e.to_string())?;
    Ok(clients
        .into_iter()
        .find(|c| c.pid == std::process::id() && c.title == PRODUCT_NAME))
}

fn apply(
    anchor: Anchor,
    requested: u32,
    generation: &Generation,
    expected: u64,
) -> Result<(), String> {
    let monitors = parse_monitors(&command(&["monitors", "-j"])?).map_err(|e| e.to_string())?;
    let frame = frame(anchor, &monitors, requested).ok_or("No valid monitor")?;
    for attempt in 0..25 {
        if !is_current(generation, expected) {
            return Ok(());
        }
        if own_client()?.is_some() {
            std::thread::sleep(Duration::from_millis(20));
            if !is_current(generation, expected) {
                return Ok(());
            }
            if let Some(client) = own_client()? {
                let lua = lua_for_frame(&client.address, &frame).ok_or("Invalid client address")?;
                return dispatch_if_current(generation, expected, || {
                    if !client.pinned {
                        eprintln!("Popover is not pinned (floating: {})", client.floating);
                    }
                    eval(&lua)
                });
            }
        }
        if attempt < 24 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    Err("Window not found after 25 attempts".into())
}
