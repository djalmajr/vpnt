/// Product name shown in the window title and the tray tooltip.
const PRODUCT_NAME: &str = "VPN Tray";

mod icon;
mod login_item;
mod notifications;
mod popover;
mod preferences;
mod worker;

use crate::{
    assets::{CONTENT_SECURITY_POLICY, asset},
    bridge::{Command, Reply, parse_request, trusted_origin},
    model::Snapshot,
};
use tao::{
    dpi::{LogicalPosition, LogicalSize},
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    platform::macos::{ActivationPolicy, EventLoopExtMacOS},
    window::WindowBuilder,
};
use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use wry::{NewWindowResponse, WebViewBuilder, http::Response};
use zeroize::Zeroizing;

enum UserEvent {
    Tray(TrayIconEvent),
    Ipc(Zeroizing<String>, std::time::Instant),
    Reply(Reply),
}

pub fn run(demo: bool, show: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    event_loop.set_activation_policy(ActivationPolicy::Accessory);
    let proxy = event_loop.create_proxy();
    let tray_proxy = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = tray_proxy.send_event(UserEvent::Tray(event));
    }));
    let window = WindowBuilder::new()
        .with_title(PRODUCT_NAME)
        .with_inner_size(LogicalSize::new(320.0, 360.0))
        .with_visible(false)
        .with_transparent(true)
        .with_decorations(false)
        .with_always_on_top(true)
        .with_resizable(false)
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
                let _ = proxy.send_event(UserEvent::Ipc(body, std::time::Instant::now()));
            }
        })
        .with_navigation_handler(|url| trusted_origin(&url))
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .build(&window)?;
    popover::round_corners(&window, &webview)?;
    let reply_proxy = event_loop.create_proxy();
    let application = worker::Worker::new(demo, move |reply| {
        let _ = reply_proxy.send_event(UserEvent::Reply(reply));
    })?;
    let mut icons = None;
    let mut open = false;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {
                if let Err(error) = create_tray(&mut icons) {
                    eprintln!("Could not create tray icon: {error}");
                    *control_flow = ControlFlow::Exit;
                }
                if show {
                    window.set_visible(true);
                    window.set_focus();
                    open = true;
                }
            }
            Event::UserEvent(UserEvent::Tray(TrayIconEvent::Click {
                position,
                button: MouseButton::Left | MouseButton::Right,
                button_state: MouseButtonState::Up,
                ..
            })) => {
                open = !open;
                if open {
                    let scale = window.scale_factor();
                    window.set_outer_position(LogicalPosition::new(
                        (position.x / scale - 160.0).max(0.0),
                        position.y / scale + 8.0,
                    ));
                }
                window.set_visible(open);
                if open {
                    window.set_focus();
                }
            }
            Event::UserEvent(UserEvent::Ipc(body, received)) => {
                if let Ok(request) = parse_request(&body) {
                    if matches!(request.command, Command::Quit {}) {
                        *control_flow = ControlFlow::Exit;
                    }
                    if matches!(request.command, Command::Hide {}) {
                        open = false;
                        window.set_visible(false);
                    }
                    if matches!(request.command, Command::OpenProject {}) {
                        // The bridge accepts no URL or executable from the webview.
                        std::thread::spawn(|| {
                            let _ = std::process::Command::new("/usr/bin/open")
                                .arg("https://github.com/djalmajr/vpnt")
                                .status();
                        });
                    }
                    if let Command::Resize { height } = request.command {
                        window.set_inner_size(LogicalSize::new(320, height.clamp(180, 720)));
                    }
                    let id = request.id.clone();
                    if application.send(request, received).is_err() {
                        let reply = Reply {
                            id,
                            snapshot: None,
                            error: Some("backend_unavailable".into()),
                        };
                        // A failed request is never a verified tunnel.
                        show_icon(&mut icons, reply.snapshot.as_ref(), reply.error.is_some());
                        if let Ok(json) = serde_json::to_string(&reply) {
                            let _ =
                                webview.evaluate_script(&format!("window.__vpntReply?.({json})"));
                        }
                    }
                }
            }
            Event::UserEvent(UserEvent::Reply(reply)) => {
                // The tray follows the same reply the webview receives, before
                // it is serialized.
                show_icon(&mut icons, reply.snapshot.as_ref(), reply.error.is_some());
                if let Ok(json) = serde_json::to_string(&reply) {
                    let _ = webview.evaluate_script(&format!("window.__vpntReply?.({json})"));
                }
            }

            Event::WindowEvent {
                event: WindowEvent::Focused(false) | WindowEvent::CloseRequested,
                ..
            } => {
                open = false;
                window.set_visible(false);
            }
            _ => {}
        }
    });
}

/// Builds the status item at menu-bar size and puts the open lock on it, before
/// the item first draws and before any snapshot proves otherwise.
fn create_tray(icons: &mut Option<icon::Controller>) -> Result<(), String> {
    let placeholder = icon::placeholder().map_err(|error| error.to_string())?;
    let tray = TrayIconBuilder::new()
        .with_icon_templated(placeholder)
        .with_tooltip(icon::TOOLTIP)
        .with_menu_on_left_click(false)
        .with_menu_on_right_click(false)
        .build()
        .map_err(|error| error.to_string())?;
    *icons = Some(icon::Controller::new(tray).map_err(|error| error.to_string())?);
    Ok(())
}

/// Applies the reply's icon, reporting a symbol AppKit cannot resolve instead of
/// keeping a stale reading silently.
fn show_icon(icons: &mut Option<icon::Controller>, snapshot: Option<&Snapshot>, error: bool) {
    let Some(controller) = icons else {
        return;
    };
    if let Err(error) = controller.show(snapshot, error) {
        eprintln!("Could not update tray icon: {error}");
    }
}
