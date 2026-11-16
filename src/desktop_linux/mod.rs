const PRODUCT_NAME: &str = "VPN Tray";

mod backend;
mod icon;
mod placement;
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
    window::WindowBuilder,
};
use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use wry::{NewWindowResponse, WebViewBuilder, WebViewBuilderExtUnix, http::Response};
use zeroize::Zeroizing;

enum UserEvent {
    Tray(TrayIconEvent, Option<placement::Anchor>),
    Ipc(Zeroizing<String>, Instant),
    Reply(Reply),
}

pub fn run(demo: bool, show: bool) -> Result<(), Box<dyn std::error::Error>> {
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let tray_proxy = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = tray_proxy.send_event(UserEvent::Tray(event, placement::capture()));
    }));
    let window = WindowBuilder::new()
        .with_title(PRODUCT_NAME)
        .with_inner_size(LogicalSize::new(320.0, 360.0))
        .with_visible(false)
        .with_transparent(true)
        .with_decorations(false)
        .with_always_on_top(true)
        .with_resizable(false)
        .with_skip_taskbar(true)
        .with_rgba_visual(true)
        .build(&event_loop)?;
    let webview = WebViewBuilder::new()
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
    let mut anchor = None;
    let mut height = 360;
    let mut last_focus_hide = None;
    let mut placement_ready = false;
    let generation = Arc::new(placement::Generation::default());
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {
                placement_ready = placement::prepare();
                let result = icon::open_lock()
                    .map_err(|error| error.to_string())
                    .and_then(|icon| {
                        TrayIconBuilder::new()
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
                    anchor = placement::capture();
                    let current = placement::advance(&generation);
                    placement::reposition(
                        &window,
                        anchor.filter(|_| placement_ready),
                        height,
                        &generation,
                        current,
                    );
                    window.set_visible(true);
                    window.set_focus();
                    open = true;
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
                if open {
                    anchor = click;
                    placement::reposition(
                        &window,
                        anchor.filter(|_| placement_ready),
                        height,
                        &generation,
                        current,
                    );
                }
                window.set_visible(open);
                if open {
                    window.set_focus();
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
                        if open {
                            let current = placement::advance(&generation);
                            placement::reposition(
                                &window,
                                anchor.filter(|_| placement_ready),
                                height,
                                &generation,
                                current,
                            );
                        } else {
                            window.set_inner_size(LogicalSize::new(320, height.clamp(180, 720)));
                        }
                    }
                    let id = request.id.clone();
                    if backend.send(request, received).is_err() {
                        send_reply(
                            &webview,
                            &Reply {
                                id,
                                snapshot: None,
                                error: Some("backend_unavailable".into()),
                            },
                        );
                    }
                }
            }
            Event::UserEvent(UserEvent::Reply(reply)) => send_reply(&webview, &reply),
            Event::WindowEvent {
                event: WindowEvent::Resized(size),
                ..
            } => {
                let logical = size.to_logical::<u32>(window.scale_factor());
                if placement_ready
                    && logical.width == 320
                    && logical.height == height.clamp(180, 720)
                {
                    let fixed = LogicalSize::new(320, logical.height);
                    window.set_min_inner_size(Some(fixed));
                    window.set_max_inner_size(Some(fixed));
                }
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
                window.set_visible(false);
            }
            _ => {}
        }
        let _ = &tray;
    });
}

fn suppress_click(hidden_at: Option<Instant>, now: Instant) -> bool {
    hidden_at.is_some_and(|time| now.saturating_duration_since(time) <= Duration::from_millis(400))
}

fn send_reply(webview: &wry::WebView, reply: &Reply) {
    if let Ok(json) = serde_json::to_string(reply) {
        let _ = webview.evaluate_script(&format!("window.__vpntReply?.({json})"));
    }
}
