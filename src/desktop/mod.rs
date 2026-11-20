/// Product name shown in the window title and the tray tooltip.
const PRODUCT_NAME: &str = "VPN Tray";

mod edit_menu;
mod icon;
mod login_item;
mod notifications;
mod placement;
mod popover;
mod preferences;
mod worker;

use crate::{
    assets::{CONTENT_SECURITY_POLICY, asset},
    bridge::{Command, Reply, parse_request, trusted_origin},
    model::Snapshot,
};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};
use tao::{
    dpi::LogicalSize,
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    platform::macos::{ActivationPolicy, EventLoopExtMacOS},
    window::{Window, WindowBuilder},
};
use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use wry::{NewWindowResponse, WebViewBuilder, http::Response};
use zeroize::Zeroizing;

enum UserEvent {
    /// The click's cursor anchor is read inside the callback, not here.
    Tray(TrayIconEvent, placement::Anchor),
    Ipc(Zeroizing<String>, std::time::Instant),
    /// A reply that may carry the authoritative snapshot.
    Reply(Reply),
    /// A reply to a metadata request: the webview receives it, the tray keeps
    /// the reading it already has.
    Metadata(Reply),
}

/// Requests the actor answers from a metadata source; their answer never
/// carries the authoritative snapshot.
fn metadata_request(command: &Command) -> bool {
    matches!(command, Command::ListCertificates { .. })
}

/// Routes one actor reply by the request it answers: a metadata answer is
/// delivered without taking the snapshot path that moves the tray icon.
fn reply_event(reply: Reply, pending: &Mutex<HashSet<String>>) -> UserEvent {
    let metadata = pending
        .lock()
        .map(|mut pending| pending.remove(&reply.id))
        .unwrap_or(false);
    if metadata {
        UserEvent::Metadata(reply)
    } else {
        UserEvent::Reply(reply)
    }
}

pub fn run(demo: bool, show: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    event_loop.set_activation_policy(ActivationPolicy::Accessory);
    let proxy = event_loop.create_proxy();
    let tray_proxy = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = tray_proxy.send_event(UserEvent::Tray(event, placement::capture()));
    }));
    let window = WindowBuilder::new()
        .with_title(PRODUCT_NAME)
        .with_inner_size(LogicalSize::new(
            320.0,
            f64::from(placement::DEFAULT_HEIGHT),
        ))
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
    let pending_metadata = Arc::new(Mutex::new(HashSet::new()));
    let reply_metadata = pending_metadata.clone();
    let application = worker::Worker::new(demo, move |reply| {
        let _ = reply_proxy.send_event(reply_event(reply, &reply_metadata));
    })?;
    let mut icons = None;
    let mut native_edit = None;
    let mut open = false;
    // Cursor at the last open, and the height the web UI last asked for.
    let mut anchor = None;
    let mut height = placement::DEFAULT_HEIGHT;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {
                // Cmd+V/C/X/A/Z reach the focused field through AppKit's
                // responder chain only when a main menu binds them.
                match edit_menu::EditMenu::install(Default::default()) {
                    Ok(menu) => native_edit = Some(menu),
                    Err(error) => eprintln!("Could not create edit menu: {error}"),
                }
                if let Err(error) = create_tray(&mut icons) {
                    eprintln!("Could not create tray icon: {error}");
                    *control_flow = ControlFlow::Exit;
                }
                if show {
                    anchor = Some(placement::capture());
                    reposition(&window, anchor, height);
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
                open = !open;
                if open {
                    // Every open re-reads the clicked screen.
                    anchor = Some(click);
                    reposition(&window, anchor, height);
                }
                window.set_visible(open);
                if open {
                    window.set_focus();
                }
            }
            Event::UserEvent(UserEvent::Ipc(body, received)) => {
                if let Ok(request) = parse_request(&body) {
                    // The request carries the UI's effective language; the
                    // menu relabels only when it changes.
                    if let (Some(menu), Some(locale)) = (native_edit.as_mut(), request.locale) {
                        menu.set_locale(locale);
                    }
                    if synchronous_metadata(&request.command)
                        && let Some(reply) =
                            crate::bridge::ovpn::reply(&request.id, &request.command)
                    {
                        if let Ok(json) = serde_json::to_string(&reply) {
                            let _ =
                                webview.evaluate_script(&format!("window.__vpntReply?.({json})"));
                        }
                        // Metadata replies do not change the authoritative tray snapshot.
                        return;
                    }
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
                    if let Command::Resize { height: requested } = request.command {
                        height = requested;
                        reposition(&window, anchor, height);
                    }
                    let id = request.id.clone();
                    let metadata = metadata_request(&request.command);
                    if metadata && let Ok(mut pending) = pending_metadata.lock() {
                        // Recorded before the send: the actor may answer first.
                        pending.insert(id.clone());
                    }
                    if application.send(request, received).is_err() {
                        if metadata && let Ok(mut pending) = pending_metadata.lock() {
                            pending.remove(&id);
                        }
                        let reply = Reply::error(id, "backend_unavailable");
                        // A failed metadata request proves nothing about the tunnel.
                        if !metadata {
                            // A failed request is never a verified tunnel.
                            show_icon(&mut icons, reply.snapshot.as_ref(), reply.error.is_some());
                        }
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
            Event::UserEvent(UserEvent::Metadata(reply)) => {
                // A metadata answer never updates the authoritative tray snapshot.
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

/// Certificate listing can wait on the token module, so it runs in the actor;
/// this callback answers only metadata that cannot block.
fn synchronous_metadata(command: &Command) -> bool {
    !matches!(command, Command::ListCertificates { .. })
}

/// Places the panel under `anchor` on its screen; without an anchor, or when
/// AppKit placement fails, only the size follows the request.
fn reposition(window: &Window, anchor: Option<placement::Anchor>, height: u32) {
    if let Some(anchor) = anchor {
        match placement::apply(window, anchor, height) {
            Ok(()) => return,
            Err(error) => eprintln!("Could not place popover: {error}"),
        }
    }
    window.set_inner_size(LogicalSize::new(320, height.clamp(180, 720)));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_callback_answers_only_metadata_that_cannot_block() {
        assert!(!synchronous_metadata(&Command::ListCertificates {
            module: "/fixture/token.dylib".into()
        }));
        assert!(synchronous_metadata(&Command::InspectOvpn {
            content: "<ca>fixture</ca>".into()
        }));
    }

    #[test]
    fn a_certificate_listing_reply_never_moves_the_tray_icon() {
        use crate::{
            app::App,
            bridge::{CertificateView, Request},
            keychain::MacKeychain,
            model::VpnKind,
            session::ConnectionState,
        };
        use std::{
            sync::mpsc,
            time::{Duration, Instant},
        };

        // A verified SSL tunnel is on the tray before any listing runs.
        let mut snapshot = App::demo().snapshot();
        snapshot.demo = false;
        snapshot.helper = "installed";
        snapshot.vpns.truncate(1);
        snapshot.vpns[0].profile.kind = VpnKind::Ssl;
        snapshot.vpns[0].state = ConnectionState::Connected;
        let prior = icon::icon_for(Some(&snapshot), false);
        assert_eq!(prior, icon::Icon::Ssl);

        // The real actor answers a listing the webview asks for.
        let (tx, rx) = mpsc::channel();
        let application = worker::Worker::spawn::<MacKeychain>(
            || (None, None),
            move |reply| {
                let _ = tx.send(reply);
            },
        )
        .unwrap();
        let pending = Mutex::new(HashSet::new());
        let ask = |id: &str, module: &str| {
            let command = Command::ListCertificates {
                module: module.into(),
            };
            assert!(metadata_request(&command));
            // The IPC arm records the id before the send.
            pending.lock().unwrap().insert(id.to_owned());
            application
                .send(
                    Request {
                        id: id.into(),
                        locale: None,
                        command,
                    },
                    Instant::now(),
                )
                .unwrap();
        };
        ask("listing-error", "relative.dylib");
        let failed = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(failed.error.as_deref(), Some("invalid_module"));
        assert!(failed.snapshot.is_none());
        // The selector this reply skips would have moved the icon.
        assert_eq!(
            icon::icon_for(failed.snapshot.as_ref(), failed.error.is_some()),
            icon::Icon::Warning
        );
        assert!(matches!(
            reply_event(failed, &pending),
            UserEvent::Metadata(_)
        ));

        // The success shape the actor returns when the module answers.
        let listed = Reply {
            id: "listing-ok".into(),
            certificates: Some(vec![CertificateView {
                id: "000aff".into(),
                subject: Some("subject".into()),
                issuer: None,
                not_before: None,
                not_after: None,
            }]),
            ..Reply::default()
        };
        pending.lock().unwrap().insert("listing-ok".into());
        assert_eq!(
            icon::icon_for(listed.snapshot.as_ref(), listed.error.is_some()),
            icon::Icon::Open
        );
        assert!(matches!(
            reply_event(listed, &pending),
            UserEvent::Metadata(_)
        ));

        // The control: a snapshot reply still takes the tray path.
        let event = reply_event(
            Reply::from_result("snapshot".into(), Ok(snapshot)),
            &pending,
        );
        let UserEvent::Reply(reply) = &event else {
            panic!("a snapshot reply must move the tray");
        };
        assert_eq!(
            icon::icon_for(reply.snapshot.as_ref(), reply.error.is_some()),
            prior
        );
        drop(application);
    }
}
