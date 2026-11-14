//! Menu-bar icon: the pure selection from a [`Snapshot`] and the native AppKit
//! adapter that loads the SF Symbol it names.
//!
//! The symbols mirror the SwiftBar menu-bar mapping the owner already reads, so
//! the tray keeps the same vocabulary: shield = IPsec, lock = SSL, stacked
//! locks = both, open lock = nothing verified, warning triangle = attention.
//! Selection is pure and exhaustively tested; only [`Controller`] touches
//! AppKit.

use crate::model::{Snapshot, VpnKind};
use crate::session::ConnectionState;
use objc2::MainThreadMarker;
use objc2::rc::Retained;
use objc2_app_kit::{NSCellImagePosition, NSImage, NSStatusBarButton, NSStatusItem};
use objc2_foundation::{NSSize, NSString};
use std::collections::BTreeMap;
use tray_icon::TrayIcon as Tray;

#[cfg(test)]
#[path = "icon/tests.rs"]
mod tests;

/// Menu-bar items are smaller than the tray library's 22 pt custom-icon cap, so
/// a symbol is fitted to 18 pt of height with its own aspect ratio.
const SYMBOL_HEIGHT: f64 = 18.0;

/// The status item's tooltip, and the one string re-applied to make the tray
/// library refresh its click target after the image changes.
pub(crate) const TOOLTIP: &str = super::PRODUCT_NAME;

/// Side of the transparent placeholder, in pixels and in points: the same
/// 18 pt the symbols are fitted to.
const PLACEHOLDER: u32 = 18;

/// The only helper marker that proves an authoritative snapshot came from an
/// installed helper (`src/broker/snapshot.rs:123`). Anything else is unverified.
const INSTALLED: &str = "installed";

/// One menu-bar reading. Every variant names a real SF Symbol; there is no
/// invented fallback, because a missing symbol must surface as an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Icon {
    /// Nothing verified connected, or no authoritative snapshot yet.
    Open,
    /// IPsec connected.
    Ipsec,
    /// SSL connected.
    Ssl,
    /// Both kinds connected.
    Both,
    /// Attention: unresponsive, error, transitional or unverified helper.
    Warning,
}

impl Icon {
    /// Every reading the selector can produce. Creation resolves all of them, so
    /// a new variant cannot ship without a symbol.
    pub(crate) const ALL: [Self; 5] = [
        Self::Open,
        Self::Ipsec,
        Self::Ssl,
        Self::Both,
        Self::Warning,
    ];

    pub(crate) fn symbol(self) -> &'static str {
        match self {
            Self::Open => "lock.open",
            Self::Ipsec => "lock.shield.fill",
            Self::Ssl => "lock.fill",
            Self::Both => "lock.square.stack.fill",
            Self::Warning => "exclamationmark.triangle.fill",
        }
    }
}

/// Which kinds are verified connected: one bit each, so "both" is a plain union.
const IPSEC: u8 = 0b01;
const SSL: u8 = 0b10;
const BOTH: u8 = IPSEC | SSL;

/// Chooses the menu-bar icon for one reply.
///
/// `error` marks a failed reply. It always wins, even when the reply also
/// carries a snapshot: a failed request never proves a tunnel, so the tray must
/// not keep showing a closed lock from a possibly stale state.
pub(crate) fn icon_for(snapshot: Option<&Snapshot>, error: bool) -> Icon {
    if error {
        return Icon::Warning;
    }
    let Some(snapshot) = snapshot else {
        // No authoritative snapshot yet: never claim a verified tunnel.
        return Icon::Open;
    };
    // A demonstration is never presented as a real tunnel, whatever its
    // simulated states say.
    if snapshot.demo {
        return Icon::Open;
    }
    // A privileged component operation, or a helper that is not the installed
    // one ("missing", "outdated", or any marker that is not proof), is
    // attention rather than a closed lock.
    if snapshot.component_operation.is_some() || snapshot.helper != INSTALLED {
        return Icon::Warning;
    }
    let mut kinds = 0_u8;
    for view in &snapshot.vpns {
        match view.state {
            // Only a connected state is a verified tunnel.
            ConnectionState::Connected => {
                kinds |= match view.profile.kind {
                    VpnKind::Ipsec => IPSEC,
                    VpnKind::Ssl => SSL,
                };
            }
            ConnectionState::Off => {}
            // Unresponsive, error and transitional states all need attention,
            // and attention outranks any verified profile.
            _ => return Icon::Warning,
        }
    }
    match kinds {
        IPSEC => Icon::Ipsec,
        SSL => Icon::Ssl,
        BOTH => Icon::Both,
        _ => Icon::Open,
    }
}

/// A menu-bar-sized transparent icon.
///
/// The tray library captures its click target's frame when the status item is
/// created and refreshes it only from its own setters, so the item must be born
/// with a real size. The open lock replaces this placeholder in the same
/// main-thread callback, before the first draw.
pub(crate) fn placeholder() -> Result<tray_icon::Icon, Error> {
    let rgba = vec![0_u8; (PLACEHOLDER * PLACEHOLDER * 4) as usize];
    tray_icon::Icon::from_rgba(rgba, PLACEHOLDER, PLACEHOLDER).map_err(|_| Error::Placeholder)
}

/// Owns the status item's image.
///
/// Every reading is resolved during [`Controller::new`], before a verified closed
/// lock can be shown, so an unavailable symbol fails creation instead of leaving
/// a stale icon at runtime. After that, applying an icon only touches the cached
/// image and the typed button.
pub(crate) struct Controller {
    tray: Tray,
    button: Retained<NSStatusBarButton>,
    applied: Option<Icon>,
    images: BTreeMap<Icon, Retained<NSImage>>,
}

impl Controller {
    /// Resolves all five symbols, then puts the open lock on the status item
    /// before it first draws. A symbol AppKit cannot resolve fails here.
    pub(crate) fn new(tray: Tray) -> Result<Self, Error> {
        let marker = MainThreadMarker::new().ok_or(Error::NotMainThread)?;
        let item: Retained<NSStatusItem> = tray.ns_status_item().ok_or(Error::NoStatusItem)?;
        let button = item.button(marker).ok_or(Error::NoButton)?;
        let mut images = BTreeMap::new();
        for icon in Icon::ALL {
            images.insert(icon, load(icon)?);
        }
        let mut controller = Self {
            tray,
            button,
            applied: None,
            images,
        };
        controller.apply(Icon::Open)?;
        Ok(controller)
    }

    /// Applies the icon the reply proves. An error reply shows attention.
    pub(crate) fn show(&mut self, snapshot: Option<&Snapshot>, error: bool) -> Result<(), Error> {
        self.apply(icon_for(snapshot, error))
    }

    fn apply(&mut self, next: Icon) -> Result<(), Error> {
        // An unchanged reading does no work: the image is already on the button.
        if self.applied == Some(next) {
            return Ok(());
        }
        let image = self
            .images
            .get(&next)
            .ok_or(Error::MissingSymbol(next))?
            .clone();
        self.button.setImage(Some(&image));
        // The tray library uses the same position when it sets an image itself.
        self.button.setImagePosition(NSCellImagePosition::ImageLeft);
        // Re-applying the unchanged tooltip is the library's public way to
        // resize its click target to the button frame the new image produced.
        self.tray
            .set_tooltip(Some(TOOLTIP))
            .map_err(|_| Error::Resync)?;
        self.applied = Some(next);
        Ok(())
    }
}

/// Fits a symbol to the menu bar height without changing its aspect ratio.
/// A symbol that reports no height is left alone rather than divided by zero.
fn fitted(size: NSSize) -> NSSize {
    if size.height <= 0.0 {
        return size;
    }
    let scale = SYMBOL_HEIGHT / size.height;
    NSSize::new(size.width * scale, SYMBOL_HEIGHT)
}

/// Resolves one SF Symbol through AppKit as a template image, scaled to the
/// menu bar with its aspect ratio preserved.
fn load(icon: Icon) -> Result<Retained<NSImage>, Error> {
    let name = NSString::from_str(icon.symbol());
    let image = NSImage::imageWithSystemSymbolName_accessibilityDescription(&name, None)
        .ok_or(Error::MissingSymbol(icon))?;
    image.setSize(fitted(image.size()));
    // Template ink follows the menu-bar appearance.
    image.setTemplate(true);
    Ok(image)
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Error {
    NotMainThread,
    NoStatusItem,
    NoButton,
    Resync,
    Placeholder,
    MissingSymbol(Icon),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotMainThread => f.write_str("tray icon update is not on the main thread"),
            Self::NoStatusItem => f.write_str("tray has no status item"),
            Self::NoButton => f.write_str("tray status item has no button"),
            Self::Resync => f.write_str("tray click target could not be refreshed"),
            Self::Placeholder => f.write_str("tray placeholder icon was rejected"),
            Self::MissingSymbol(icon) => {
                write!(f, "SF Symbol {} is unavailable", icon.symbol())
            }
        }
    }
}
