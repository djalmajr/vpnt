//! Popover placement on the screen that was clicked.
//!
//! Everything is in Cocoa points (origin at the bottom-left of the primary
//! display, y up). The tray click captures `NSEvent.mouseLocation` as an
//! [`Anchor`], a plain `Copy + Send` pair of numbers, so moving the cursor
//! afterwards cannot change the target screen. No window scale factor is
//! involved: AppKit applies the computed frame in points directly.
//!
//! The screen choice, the 8 pt side margin, the 24 pt bottom margin and the
//! menu-bar fallback follow `src/tray/panel.rs` and `src/tray/host_macos.rs`
//! (`screen_pair_containing`, `menu_bar_bottom_y`, `cocoa_popover_frame`) of
//! ai-usagebar, commit 4f9d73f2, MIT, Copyright (c) 2026 AkitaOnRails. The code
//! is a rewrite, not a verbatim copy; the 85% height cap, the status-item
//! window probe and the 360 pt minimum height of the reference are not used.

use objc2::MainThreadMarker;
use objc2_app_kit::{NSEvent, NSScreen, NSWindow};
use objc2_foundation::{NSPoint, NSRect, NSSize};
use std::io::{Error, Result};
use tao::{platform::macos::WindowExtMacOS, window::Window};

/// Desired panel width; only narrowed when the screen cannot hold it.
const PANEL_WIDTH: f64 = 320.0;
/// Bounds of the height the web UI may request (`Command::Resize`).
const MIN_HEIGHT: f64 = 180.0;
const MAX_HEIGHT: f64 = 720.0;
/// Inset from the left and right edges of the visible screen.
const SIDE_MARGIN: f64 = 8.0;
/// Gap above the bottom of the visible screen (dock or desktop).
const BOTTOM_MARGIN: f64 = 24.0;
/// The panel hangs directly under the menu bar (0 pt gap); this is the bar
/// height assumed when `visibleFrame` does not subtract it.
const MENU_BAR_MIN_HEIGHT: f64 = 24.0;

/// Cursor position at the moment of a tray click, in Cocoa points.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Anchor {
    x: f64,
    y: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Rect {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

impl Rect {
    fn max_x(self) -> f64 {
        self.x + self.w
    }

    fn max_y(self) -> f64 {
        self.y + self.h
    }

    /// Half-open, so a point on a shared edge belongs to exactly one screen.
    fn contains(self, anchor: Anchor) -> bool {
        anchor.x >= self.x
            && anchor.x < self.max_x()
            && anchor.y >= self.y
            && anchor.y < self.max_y()
    }

    /// Includes the far edges: the cursor can rest exactly on the top row.
    fn touches(self, anchor: Anchor) -> bool {
        anchor.x >= self.x
            && anchor.x <= self.max_x()
            && anchor.y >= self.y
            && anchor.y <= self.max_y()
    }
}

/// One `NSScreen`: its full frame and the part not covered by bar and dock.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Screen {
    frame: Rect,
    visible: Rect,
}

/// The screen holding the anchor; the primary one (first in `NSScreen.screens`)
/// when the anchor lies outside every screen, for example after a removal.
fn screen_for(screens: &[Screen], anchor: Anchor) -> Option<Screen> {
    screens
        .iter()
        .find(|screen| screen.frame.contains(anchor))
        .or_else(|| screens.iter().find(|screen| screen.frame.touches(anchor)))
        .or_else(|| screens.first())
        .copied()
}

/// Panel frame for `requested_height` on the screen under `anchor`, or `None`
/// when no screen exists. Sizes shrink only to fit the screen and never exceed
/// their limits.
fn panel_frame(screens: &[Screen], anchor: Anchor, requested_height: u32) -> Option<Rect> {
    let Screen { frame, visible } = screen_for(screens, anchor)?;
    // `visibleFrame` normally excludes the menu bar; when it does not, assume
    // the minimum bar height rather than overlapping it.
    let bar = (frame.max_y() - visible.max_y()).max(MENU_BAR_MIN_HEIGHT);
    let top = frame.max_y() - bar;
    let bottom = visible.y + BOTTOM_MARGIN;
    let available = (top - bottom).max(1.0);
    let height = f64::from(requested_height)
        .clamp(MIN_HEIGHT, MAX_HEIGHT)
        .min(available);
    let width = PANEL_WIDTH.min((visible.w - 2.0 * SIDE_MARGIN).max(1.0));
    let min_x = visible.x + SIDE_MARGIN;
    let max_x = (visible.max_x() - SIDE_MARGIN - width).max(min_x);
    Some(Rect {
        x: (anchor.x - width / 2.0).clamp(min_x, max_x),
        y: top - height,
        w: width,
        h: height,
    })
}

/// Reads the cursor. Call it synchronously from the tray click callback.
pub(super) fn capture() -> Anchor {
    let point = NSEvent::mouseLocation();
    Anchor {
        x: point.x,
        y: point.y,
    }
}

/// Moves and sizes the window for `anchor` in one AppKit frame change.
/// Main thread only.
pub(super) fn apply(window: &Window, anchor: Anchor, requested_height: u32) -> Result<()> {
    let main_thread = MainThreadMarker::new()
        .ok_or_else(|| Error::other("popover placement requires the main thread"))?;
    let screens: Vec<Screen> = NSScreen::screens(main_thread)
        .iter()
        .map(|screen| Screen {
            frame: rect(screen.frame()),
            visible: rect(screen.visibleFrame()),
        })
        .collect();
    let frame = panel_frame(&screens, anchor, requested_height)
        .ok_or_else(|| Error::other("no screen available for the popover"))?;
    let pointer = window.ns_window().cast::<NSWindow>();
    // SAFETY: Tao returns its live NSWindow. The borrowed Window outlives this
    // synchronous main-thread call; the checked reference never escapes it.
    let native =
        unsafe { pointer.as_ref() }.ok_or_else(|| Error::other("popover has no native window"))?;
    native.setFrame_display(
        NSRect::new(
            NSPoint::new(frame.x, frame.y),
            NSSize::new(frame.w, frame.h),
        ),
        true,
    );
    Ok(())
}

fn rect(value: NSRect) -> Rect {
    Rect {
        x: value.origin.x,
        y: value.origin.y,
        w: value.size.width,
        h: value.size.height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: f64, y: f64, w: f64, h: f64) -> Rect {
        Rect { x, y, w, h }
    }

    fn at(x: f64, y: f64) -> Anchor {
        Anchor { x, y }
    }

    /// A screen whose visible frame loses `bar` at the top and `dock` at the bottom.
    fn screen(x: f64, y: f64, w: f64, h: f64, bar: f64, dock: f64) -> Screen {
        Screen {
            frame: rect(x, y, w, h),
            visible: rect(x, y + dock, w, h - bar - dock),
        }
    }

    fn primary() -> Screen {
        screen(0.0, 0.0, 1440.0, 900.0, 24.0, 0.0)
    }

    fn frame(screens: &[Screen], anchor: Anchor, height: u32) -> Rect {
        panel_frame(screens, anchor, height).expect("screens are not empty")
    }

    #[test]
    fn anchor_is_plain_send_numbers() {
        fn send<T: Send + Copy + 'static>() {}
        send::<Anchor>();
    }

    #[test]
    fn right_hand_screen_keeps_the_panel_on_that_screen() {
        let right = screen(1440.0, 0.0, 1920.0, 1080.0, 24.0, 0.0);
        let frame = frame(&[primary(), right], at(2400.0, 1070.0), 360);
        assert_eq!(frame, rect(2240.0, 696.0, 320.0, 360.0));
    }

    #[test]
    fn left_hand_screen_keeps_its_negative_origin() {
        let left = screen(-1920.0, 0.0, 1920.0, 1080.0, 24.0, 0.0);
        let frame = frame(&[primary(), left], at(-200.0, 1070.0), 360);
        assert_eq!(frame, rect(-360.0, 696.0, 320.0, 360.0));
        let edge = self::frame(&[primary(), left], at(-1919.0, 1070.0), 360);
        assert_eq!(edge.x, -1912.0, "8 pt from the left edge of that screen");
    }

    #[test]
    fn screens_above_and_below_use_their_own_vertical_range() {
        let above = screen(0.0, 900.0, 1920.0, 1080.0, 24.0, 0.0);
        let below = screen(0.0, -1080.0, 1920.0, 1080.0, 24.0, 0.0);
        let screens = [primary(), above, below];
        let up = frame(&screens, at(500.0, 1970.0), 360);
        assert_eq!((up.y, up.max_y()), (1596.0, 1956.0));
        let down = frame(&screens, at(500.0, -10.0), 360);
        assert_eq!((down.y, down.max_y()), (-384.0, -24.0));
    }

    #[test]
    fn retina_and_non_retina_share_the_same_point_geometry() {
        // 1512x982 (retina, notch bar) and 1920x1080 (1x) both describe points.
        let retina = screen(0.0, 0.0, 1512.0, 982.0, 38.0, 0.0);
        let plain = screen(1512.0, 0.0, 1920.0, 1080.0, 24.0, 0.0);
        let screens = [retina, plain];
        let on_retina = frame(&screens, at(756.0, 975.0), 400);
        assert_eq!(on_retina, rect(596.0, 544.0, 320.0, 400.0));
        let on_plain = frame(&screens, at(1512.0 + 960.0, 1075.0), 400);
        assert_eq!(on_plain, rect(1512.0 + 800.0, 656.0, 320.0, 400.0));
    }

    #[test]
    fn dock_margin_stops_a_tall_panel_above_the_dock() {
        let roomy = screen(0.0, 0.0, 1440.0, 900.0, 24.0, 70.0);
        let free = frame(&[roomy], at(700.0, 890.0), 720);
        assert_eq!((free.y, free.max_y(), free.h), (156.0, 876.0, 720.0));
        let short = screen(0.0, 0.0, 1440.0, 800.0, 24.0, 70.0);
        let fitted = frame(&[short], at(700.0, 790.0), 720);
        assert_eq!(fitted.y, 70.0 + 24.0, "24 pt above the dock");
        assert_eq!((fitted.max_y(), fitted.h), (776.0, 682.0));
    }

    #[test]
    fn horizontal_edges_use_the_side_margin() {
        let screens = [primary()];
        assert_eq!(frame(&screens, at(0.0, 890.0), 360).x, 8.0);
        assert_eq!(
            frame(&screens, at(1439.0, 890.0), 360).x,
            1440.0 - 8.0 - 320.0
        );
        assert_eq!(frame(&screens, at(720.0, 890.0), 360).x, 560.0);
    }

    #[test]
    fn click_selection_handles_shared_and_far_edges() {
        let right = screen(1440.0, 0.0, 1920.0, 1080.0, 24.0, 0.0);
        let screens = [primary(), right];
        // The shared edge belongs to the screen on its right.
        assert_eq!(screen_for(&screens, at(1440.0, 500.0)), Some(right));
        assert_eq!(screen_for(&screens, at(1439.9, 500.0)), Some(primary()));
        // The cursor can rest exactly on a screen's top edge.
        assert_eq!(screen_for(&screens, at(2000.0, 1080.0)), Some(right));
        assert_eq!(screen_for(&screens, at(100.0, 900.0)), Some(primary()));
    }

    #[test]
    fn removed_screen_falls_back_to_the_primary() {
        let right = screen(1440.0, 0.0, 1920.0, 1080.0, 24.0, 0.0);
        let click = at(2400.0, 1070.0);
        assert_eq!(screen_for(&[primary(), right], click), Some(right));
        assert_eq!(screen_for(&[primary()], click), Some(primary()));
        let frame = frame(&[primary()], click, 360);
        assert!(frame.x >= 8.0 && frame.max_x() <= 1440.0 - 8.0);
        assert_eq!(panel_frame(&[], click, 360), None);
    }

    #[test]
    fn resize_keeps_the_anchor_and_reopen_follows_the_new_one() {
        let right = screen(1440.0, 0.0, 1920.0, 1080.0, 24.0, 0.0);
        let screens = [primary(), right];
        let anchor = at(2400.0, 1070.0);
        let first = frame(&screens, anchor, 300);
        let resized = frame(&screens, anchor, 500);
        assert_eq!(first.x, resized.x);
        assert_eq!(
            first.max_y(),
            resized.max_y(),
            "the top stays under the bar"
        );
        assert_eq!((first.h, resized.h), (300.0, 500.0));
        let reopened = frame(&screens, at(300.0, 890.0), 500);
        assert_eq!(reopened, rect(140.0, 376.0, 320.0, 500.0));
    }

    #[test]
    fn sizes_follow_their_limits_without_the_reference_percentage_cap() {
        let screens = [screen(0.0, 0.0, 1440.0, 800.0, 24.0, 0.0)];
        let anchor = at(700.0, 790.0);
        assert_eq!(frame(&screens, anchor, 10).h, 180.0);
        assert_eq!(frame(&screens, anchor, 180).h, 180.0);
        assert_eq!(frame(&screens, anchor, 5000).h, 720.0);
        // 85% of the 752 pt of room would be about 639 pt; no such cap applies.
        assert_eq!(frame(&screens, anchor, 720).h, 720.0);
        assert_eq!(frame(&screens, anchor, 720).w, 320.0);
    }

    #[test]
    fn small_screens_shrink_the_panel_without_leaving_them() {
        let small = screen(100.0, 50.0, 300.0, 200.0, 24.0, 0.0);
        let frame = frame(&[small], at(250.0, 240.0), 720);
        assert_eq!(frame.w, 284.0);
        assert_eq!((frame.x, frame.max_x()), (108.0, 392.0));
        assert_eq!((frame.y, frame.max_y()), (74.0, 226.0));
    }

    #[test]
    fn menu_bar_is_at_least_24_pt_when_the_visible_frame_ignores_it() {
        let unreduced = Screen {
            frame: rect(0.0, 0.0, 1440.0, 900.0),
            visible: rect(0.0, 0.0, 1440.0, 900.0),
        };
        assert_eq!(frame(&[unreduced], at(700.0, 890.0), 360).max_y(), 876.0);
        let notch = screen(0.0, 0.0, 1512.0, 982.0, 38.0, 0.0);
        assert_eq!(frame(&[notch], at(700.0, 975.0), 360).max_y(), 944.0);
    }
}
