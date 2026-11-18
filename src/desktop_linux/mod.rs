const PRODUCT_NAME: &str = "VPN Tray";
// DESIGN.md, Conflicting visual priorities: --panel-min-height: 480px.
const DEFAULT_HEIGHT: u32 = 480;
/// StatusNotifierItem Id. Trays such as Omarchy's pin items by this Id, so it
/// must not change between runs (tray-icon's default embeds the process id).
const TRAY_ID: &str = "vpnt";

mod backend;
mod icon;
mod omarchy;
mod placement;
mod preferences;
#[cfg(test)]
mod tests;

use crate::{
    assets::{CONTENT_SECURITY_POLICY, asset},
    bridge::{Command, Reply, parse_request, trusted_origin},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tao::{
    dpi::LogicalSize,
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    platform::unix::{WindowBuilderExtUnix, WindowExtUnix},
    window::{Window, WindowBuilder},
};
use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use wry::{NewWindowResponse, WebViewBuilder, WebViewBuilderExtUnix, http::Response};
use zeroize::Zeroizing;

enum UserEvent {
    Tray(TrayIconEvent, Option<placement::Anchor>),
    Ipc(Zeroizing<String>, Instant),
    Reply(Reply),
    Theme(omarchy::Theme),
    Show {
        generation: u64,
        height: u32,
        anchor: Option<placement::Anchor>,
    },
    Placed {
        generation: u64,
        height: u32,
        anchor: Option<placement::Anchor>,
    },
}

pub fn run(demo: bool, show: bool) -> Result<(), Box<dyn std::error::Error>> {
    glib::set_prgname(Some("vpnt"));
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let detected = omarchy::detect(
        std::env::var_os("OMARCHY_PATH")
            .as_deref()
            .map(std::path::Path::new),
        std::path::Path::new("/usr/share/omarchy"),
    );
    let initial_theme = if detected {
        let theme_proxy = event_loop.create_proxy();
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        omarchy::start(omarchy::Paths::new(&home), move |theme| {
            let _ = theme_proxy.send_event(UserEvent::Theme(theme));
        })?
    } else {
        None
    };
    let proxy = event_loop.create_proxy();
    let generation = Arc::new(placement::Generation::default());
    let placement_proxy = event_loop.create_proxy();
    let positioner = placement::Positioner::new(
        Arc::clone(&generation),
        detected,
        move |generation, height, anchor, opening| {
            let event = if opening {
                UserEvent::Show {
                    generation,
                    height,
                    anchor,
                }
            } else {
                UserEvent::Placed {
                    generation,
                    height,
                    anchor,
                }
            };
            let _ = placement_proxy.send_event(event);
        },
    )?;
    let tray_proxy = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = tray_proxy.send_event(UserEvent::Tray(event, placement::capture()));
    }));
    let window = WindowBuilder::new()
        .with_title(PRODUCT_NAME)
        .with_inner_size(LogicalSize::new(320, DEFAULT_HEIGHT))
        .with_visible(false)
        .with_transparent(true)
        .with_decorations(false)
        .with_always_on_top(true)
        .with_resizable(false)
        .with_skip_taskbar(true)
        .with_rgba_visual(true)
        .build(&event_loop)?;
    let mut webview_builder = WebViewBuilder::new();
    let initial_script = if detected {
        Some(initial_theme.as_ref().map_or_else(
            || "document.documentElement.dataset.desktop='omarchy';".to_owned(),
            omarchy::script,
        ))
    } else {
        None
    };
    if let Some(script) = initial_script.as_deref() {
        webview_builder = webview_builder.with_initialization_script(script);
    }
    let webview = webview_builder
        .with_transparent(true)
        .with_custom_protocol("vpnt".into(), |_id, request| {
            let (mime, body, status) =
                if request.uri().host() == Some("localhost") && request.method() == "GET" {
                    asset(request.uri().path())
                        .map(|(mime, body)| (mime, body, 200))
                        .unwrap_or(("text/plain", &b"Not found"[..], 404))
                } else {
                    ("text/plain", &b"Forbidden"[..], 403)
                };
            Response::builder()
                .status(status)
                .header("Content-Type", mime)
                .header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
                .body(std::borrow::Cow::Borrowed(body))
                .unwrap()
        })
        .with_url("vpnt://localhost/index.html")
        .with_ipc_handler(move |request| {
            let trusted = trusted_origin(&request.uri().to_string());
            let body = Zeroizing::new(request.into_body());
            if trusted && body.len() <= 65536 {
                let _ = proxy.send_event(UserEvent::Ipc(body, Instant::now()));
            }
        })
        .with_navigation_handler(|url| trusted_origin(&url))
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .build_gtk(window.default_vbox().expect("default GTK box"))?;
    let reply_proxy = event_loop.create_proxy();
    let backend = backend::Backend::new(demo, move |reply| {
        let _ = reply_proxy.send_event(UserEvent::Reply(reply));
    })?;
    let mut tray = None;
    let mut open = false;
    let mut opening = 0;
    let mut anchor = None;
    let mut height = DEFAULT_HEIGHT;
    let mut last_focus_hide = None;
    let mut deadline: Option<Instant> = None;
    let mut visible = false;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = deadline.map_or(ControlFlow::Wait, ControlFlow::WaitUntil);
        match event {
            Event::NewEvents(StartCause::Init) => {
                let result = icon::open_lock()
                    .map_err(|error| error.to_string())
                    .and_then(|icon| {
                        TrayIconBuilder::new()
                            .with_id(TRAY_ID)
                            .with_icon(icon)
                            .with_tooltip(PRODUCT_NAME)
                            .with_title(PRODUCT_NAME)
                            .with_menu_on_left_click(false)
                            .with_menu_on_right_click(false)
                            .build()
                            .map_err(|error| error.to_string())
                    });
                match result {
                    Ok(icon) => tray = Some(icon),
                    Err(error) => {
                        eprintln!("Could not create tray icon: {error}");
                        *control_flow = ControlFlow::Exit;
                        return;
                    }
                }
                if show {
                    let current = placement::advance(&generation);
                    opening = current;
                    let queued = reposition(
                        &window,
                        &positioner,
                        placement::click_request(current, None, height),
                    );
                    open = true;
                    if queued {
                        deadline = Some(Instant::now() + Duration::from_millis(400));
                    } else {
                        window.set_visible(true);
                        window.set_focus();
                        visible = true;
                    }
                }
            }
            Event::UserEvent(UserEvent::Tray(
                TrayIconEvent::Click {
                    button: MouseButton::Left | MouseButton::Right,
                    button_state: MouseButtonState::Up,
                    ..
                },
                click,
            )) => {
                if !open && suppress_click(last_focus_hide, Instant::now()) {
                    return;
                }
                open = !open;
                let current = placement::advance(&generation);
                let mut queued = false;
                if open {
                    opening = current;
                    anchor = click;
                    queued = reposition(
                        &window,
                        &positioner,
                        placement::click_request(current, click, height),
                    );
                }
                if open && queued {
                    deadline = Some(Instant::now() + Duration::from_millis(400));
                } else {
                    deadline = None;
                    window.set_visible(open);
                    visible = open;
                    if open {
                        window.set_focus();
                    }
                }
            }
            Event::UserEvent(UserEvent::Ipc(body, received)) => {
                if let Ok(request) = parse_request(&body) {
                    if matches!(request.command, Command::Quit {}) {
                        placement::advance(&generation);
                        *control_flow = ControlFlow::Exit;
                    }
                    if matches!(request.command, Command::Hide {}) {
                        placement::advance(&generation);
                        open = false;
                        visible = false;
                        deadline = None;
                        window.set_visible(false);
                    }
                    if matches!(request.command, Command::OpenProject {}) {
                        std::thread::spawn(|| {
                            let _ = std::process::Command::new("/usr/bin/xdg-open")
                                .arg("https://github.com/djalmajr/vpnt")
                                .status();
                        });
                    }
                    if let Command::Resize { height: requested } = request.command {
                        height = requested;
                        let current = placement::advance(&generation);
                        if open && !visible {
                            opening = current;
                            reposition(
                                &window,
                                &positioner,
                                placement::click_request(current, anchor, height),
                            );
                        } else if open {
                            resize_visible(
                                &window,
                                &positioner,
                                placement::resize_request(current, opening, anchor, height),
                            );
                        } else {
                            fix_height(&window, height.clamp(180, 720));
                        }
                    }
                    let id = request.id.clone();
                    if backend.send(request, received).is_err() {
                        send_reply(&webview, &Reply::error(id, "backend_unavailable"));
                    }
                }
            }
            Event::UserEvent(UserEvent::Reply(reply)) => send_reply(&webview, &reply),
            Event::UserEvent(UserEvent::Theme(theme)) => {
                let _ = webview.evaluate_script(&omarchy::script(&theme));
            }
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) => {
                if show_decision(
                    open,
                    visible,
                    true,
                    deadline.is_some_and(|at| Instant::now() >= at),
                ) == ShowDecision::Show
                {
                    deadline = None;
                    window.set_visible(true);
                    window.set_focus();
                    visible = true;
                }
            }
            Event::UserEvent(UserEvent::Show {
                generation: placed,
                height: placed_height,
                anchor: used_anchor,
            }) => {
                let decision = show_decision(
                    open,
                    visible,
                    placement::current(&generation) == placed,
                    true,
                );
                if decision != ShowDecision::Ignore {
                    if anchor.is_none() {
                        anchor = used_anchor;
                    }
                    if decision == ShowDecision::Show {
                        fix_height(&window, placed_height);
                        window.set_visible(true);
                        window.set_focus();
                        visible = true;
                        deadline = None;
                    }
                    resize_visible(
                        &window,
                        &positioner,
                        placement::resize_request(placed, opening, anchor, height),
                    );
                }
            }
            Event::UserEvent(UserEvent::Placed {
                generation: placed,
                height,
                anchor: used_anchor,
            }) => {
                let current = placement::current(&generation);
                apply_placed(&window, current, placed, height, &mut anchor, used_anchor);
            }
            Event::WindowEvent {
                event: WindowEvent::Focused(false) | WindowEvent::CloseRequested,
                ..
            } => {
                if open {
                    last_focus_hide = Some(Instant::now());
                }
                placement::advance(&generation);
                open = false;
                visible = false;
                deadline = None;
                window.set_visible(false);
            }
            _ => {}
        }
        if !matches!(*control_flow, ControlFlow::Exit) {
            *control_flow = deadline.map_or(ControlFlow::Wait, ControlFlow::WaitUntil);
        }
        let _ = &tray;
    });
}

#[derive(Debug, PartialEq)]
enum ShowDecision {
    Ignore,
    Show,
    Reposition,
}

fn show_decision(open: bool, visible: bool, current: bool, ready: bool) -> ShowDecision {
    if !open || !current || !ready {
        ShowDecision::Ignore
    } else if visible {
        ShowDecision::Reposition
    } else {
        ShowDecision::Show
    }
}

fn accept_placement(
    current: u64,
    placed: u64,
    height: u32,
    anchor: &mut Option<placement::Anchor>,
    used_anchor: Option<placement::Anchor>,
) -> Option<u32> {
    let height = placement::applied_height(current, placed, height)?;
    if anchor.is_none() {
        *anchor = used_anchor;
    }
    Some(height)
}

/// Size operations of the panel window. The resize sequence goes through this
/// trait so tests can record its order without a display.
trait PanelWindow {
    /// Asks GTK for this height. On a visible floating window, Hyprland treats it
    /// as a client resize and keeps the window's center.
    fn set_height(&self, height: u32);
    fn release_bounds(&self);
    fn fix_bounds(&self, height: u32);
}

impl PanelWindow for Window {
    fn set_height(&self, height: u32) {
        self.set_inner_size(LogicalSize::new(320, height));
    }

    fn release_bounds(&self) {
        self.set_min_inner_size(None::<LogicalSize<u32>>);
        self.set_max_inner_size(None::<LogicalSize<u32>>);
        self.set_resizable(true);
    }

    fn fix_bounds(&self, height: u32) {
        let fixed = LogicalSize::new(320, height);
        self.set_min_inner_size(Some(fixed));
        self.set_max_inner_size(Some(fixed));
        self.set_resizable(false);
    }
}

/// Where placement requests go: the Hyprland positioner, or a test double.
trait Placer {
    fn supported(&self) -> bool;
    fn send(&self, request: placement::PlacementRequest) -> Result<(), ()>;
}

impl Placer for placement::Positioner {
    fn supported(&self) -> bool {
        placement::Positioner::supported(self)
    }

    fn send(&self, request: placement::PlacementRequest) -> Result<(), ()> {
        placement::Positioner::send(self, request)
    }
}

fn fix_height(window: &impl PanelWindow, height: u32) {
    window.set_height(height);
    window.fix_bounds(height);
}

/// Sizes the hidden panel and queues its placement; false when nothing will
/// answer and the caller shows it at once.
fn reposition(
    window: &impl PanelWindow,
    positioner: &impl Placer,
    request: placement::PlacementRequest,
) -> bool {
    let height = request.requested.clamp(180, 720);
    window.release_bounds();
    window.set_height(height);
    if !positioner.supported() || positioner.send(request).is_err() {
        window.fix_bounds(height);
        false
    } else {
        true
    }
}

/// Resizes the visible panel through Hyprland, which keeps a floating window's
/// center when the client changes its own size. A GTK window still fixed at the
/// old height turns the compositor's resize down and commits the old size back,
/// so the panel grows around its center and slides under the bar. The bounds are
/// released and GTK is not resized here; `apply_placed` fixes them at the applied
/// height.
fn resize_visible(
    window: &impl PanelWindow,
    positioner: &impl Placer,
    request: placement::PlacementRequest,
) {
    if positioner.supported() {
        window.release_bounds();
        if positioner.send(request).is_ok() {
            return;
        }
    }
    fix_height(window, request.requested.clamp(180, 720));
}

/// Fixes the panel at the height the positioner applied, or at the requested one
/// when it failed; a stale generation changes nothing.
fn apply_placed(
    window: &impl PanelWindow,
    current: u64,
    placed: u64,
    height: u32,
    anchor: &mut Option<placement::Anchor>,
    used_anchor: Option<placement::Anchor>,
) {
    if let Some(height) = accept_placement(current, placed, height, anchor, used_anchor) {
        fix_height(window, height);
    }
}

fn suppress_click(hidden_at: Option<Instant>, now: Instant) -> bool {
    hidden_at.is_some_and(|time| now.saturating_duration_since(time) <= Duration::from_millis(400))
}

fn send_reply(webview: &wry::WebView, reply: &Reply) {
    if let Ok(json) = serde_json::to_string(reply) {
        let _ = webview.evaluate_script(&format!("window.__vpntReply?.({json})"));
    }
}
