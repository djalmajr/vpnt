mod icon;

use crate::{
    app::App,
    assets::{CONTENT_SECURITY_POLICY, asset},
    bridge::{Command, Reply, parse_request, trusted_origin},
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

#[derive(Debug)]
enum UserEvent {
    Tray(TrayIconEvent),
    Ipc(String),
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
        .with_title("vpnt")
        .with_inner_size(LogicalSize::new(320.0, 360.0))
        .with_visible(false)
        .with_decorations(false)
        .with_always_on_top(true)
        .with_resizable(false)
        .build(&event_loop)?;
    let webview = WebViewBuilder::new()
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
            if trusted_origin(&request.uri().to_string()) && request.body().len() <= 65536 {
                let _ = proxy.send_event(UserEvent::Ipc(request.body().clone()));
            }
        })
        .with_navigation_handler(|url| trusted_origin(&url))
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .build(&window)?;
    let mut app = if demo { App::demo() } else { App::new() };
    let mut tray = None;
    let mut open = false;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {
                match icon::shield()
                    .map_err(|error| error.to_string())
                    .and_then(|icon| {
                        TrayIconBuilder::new()
                            .with_icon_templated(icon)
                            .with_tooltip("vpnt")
                            .with_menu_on_left_click(false)
                            .with_menu_on_right_click(false)
                            .build()
                            .map_err(|error| error.to_string())
                    }) {
                    Ok(icon) => tray = Some(icon),
                    Err(error) => {
                        eprintln!("Could not create tray icon: {error}");
                        *control_flow = ControlFlow::Exit;
                    }
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
            Event::UserEvent(UserEvent::Ipc(body)) => {
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
                    let reply = match app.dispatch(request.command) {
                        Ok(snapshot) => Reply {
                            id: request.id,
                            snapshot: Some(snapshot),
                            error: None,
                        },
                        Err(error) => Reply {
                            id: request.id,
                            snapshot: None,
                            error: Some(error.into()),
                        },
                    };
                    if let Ok(json) = serde_json::to_string(&reply) {
                        let _ = webview.evaluate_script(&format!("window.__vpntReply?.({json})"));
                    }
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
        let _ = &tray;
    });
}
