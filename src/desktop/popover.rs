//! Native outer clip for the classic opaque panel; only its corners are clear.

use objc2::MainThreadMarker;
use objc2_app_kit::{NSColor, NSView, NSWindow};
use objc2_quartz_core::kCACornerCurveContinuous;
use std::io::{Error, Result};
use tao::{platform::macos::WindowExtMacOS, window::Window};
use wry::{WebView, WebViewExtMacOS};

const CORNER_RADIUS: f64 = 13.0;

/// Run after Wry installs its content view, before the hidden window is shown.
/// AppKit resizes the backing layers with their views, so the rounded bounds
/// follow subsequent Tao/Wry resizes without a fixed-size mask or timer.
pub(super) fn round_corners(window: &Window, webview: &WebView) -> Result<()> {
    let _main_thread = MainThreadMarker::new()
        .ok_or_else(|| Error::other("popover clipping requires the main thread"))?;
    let pointer = window.ns_window().cast::<NSWindow>();
    // SAFETY: Tao returns its live NSWindow. The borrowed Window outlives this
    // synchronous main-thread call; the checked reference never escapes it.
    let native =
        unsafe { pointer.as_ref() }.ok_or_else(|| Error::other("popover has no native window"))?;
    let content = native
        .contentView()
        .ok_or_else(|| Error::other("popover has no content view"))?;
    // The public Wry handle retains the actual WKWebView, not an arbitrary
    // descendant found by traversal. Both views stay alive throughout this call.
    let child = webview.webview();
    round_view(&content)?;
    round_view(&child)?;
    native.setOpaque(false);
    native.setBackgroundColor(Some(&NSColor::clearColor()));
    Ok(())
}

fn round_view(view: &NSView) -> Result<()> {
    view.setWantsLayer(true);
    let layer = view
        .layer()
        .ok_or_else(|| Error::other("popover view has no backing layer"))?;
    layer.setCornerRadius(CORNER_RADIUS);
    layer.setMasksToBounds(true);
    // SAFETY: this system constant is a process-lifetime corner-curve string;
    // macOS 13 (the app minimum) supports continuous corners. The setter copies it.
    unsafe { layer.setCornerCurve(kCACornerCurveContinuous) };
    Ok(())
}
