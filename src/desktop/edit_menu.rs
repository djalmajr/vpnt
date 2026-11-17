//! Native Edit menu for the WebView host.
//!
//! `tao` creates no `NSMenu` and `wry` only forwards key events to
//! `NSApplication.mainMenu`, so without a main menu nothing translates
//! Cmd+V/C/X/A/Z into the standard AppKit editing actions. This module installs
//! one as `NSApp.mainMenu` using the `muda` predefined items that `tray-icon`
//! already re-exports. Each item targets `nil`, so AppKit sends `undo:`,
//! `redo:`, `cut:`, `copy:`, `paste:` and `selectAll:` down the responder chain
//! to the focused `WKWebView`, which edits the focused field itself. The
//! clipboard is never read, written or bridged here, and the web content,
//! its CSP and the IPC schema are untouched.
//!
//! The menu is built and updated on the UI thread only (`muda` asserts it).

use crate::localization::Locale;
use serde::Deserialize;
use std::collections::BTreeMap;
use tray_icon::menu::{Menu, PredefinedMenuItem, Submenu};

/// Shared pt-BR/en-US catalog; the `Locale` codes are its keys.
const CATALOG: &str = include_str!("../../ui/src/locales/menus.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Messages {
    edit: String,
    undo: String,
    redo: String,
    cut: String,
    copy: String,
    paste: String,
    select_all: String,
}

fn messages(locale: Locale) -> Result<Messages, String> {
    let mut catalogs: BTreeMap<String, Messages> =
        serde_json::from_str(CATALOG).map_err(|error| format!("menu catalog: {error}"))?;
    catalogs
        .remove(locale.code())
        .ok_or_else(|| format!("menu catalog has no {}", locale.code()))
}

/// Owns the installed menu so it lives as long as the event loop.
pub(super) struct EditMenu {
    /// Never read: it keeps the `NSMenu` tree and its items alive.
    _menu: Menu,
    edit: Submenu,
    undo: PredefinedMenuItem,
    redo: PredefinedMenuItem,
    cut: PredefinedMenuItem,
    copy: PredefinedMenuItem,
    paste: PredefinedMenuItem,
    select_all: PredefinedMenuItem,
    locale: Locale,
}

impl EditMenu {
    /// Installs `NSApp.mainMenu`. Must run on the main thread, inside the
    /// running event loop.
    pub(super) fn install(locale: Locale) -> Result<Self, String> {
        let text = messages(locale)?;
        let undo = PredefinedMenuItem::undo(Some(&text.undo));
        let redo = PredefinedMenuItem::redo(Some(&text.redo));
        let cut = PredefinedMenuItem::cut(Some(&text.cut));
        let copy = PredefinedMenuItem::copy(Some(&text.copy));
        let paste = PredefinedMenuItem::paste(Some(&text.paste));
        let select_all = PredefinedMenuItem::select_all(Some(&text.select_all));
        let separator = PredefinedMenuItem::separator();
        let edit = Submenu::with_items(
            &text.edit,
            true,
            &[&undo, &redo, &separator, &cut, &copy, &paste, &select_all],
        )
        .map_err(|error| error.to_string())?;
        // AppKit treats the first main-menu entry as the application menu. It
        // carries no actions: Edit must not take that slot.
        let application = Submenu::with_items(super::PRODUCT_NAME, true, &[])
            .map_err(|error| error.to_string())?;
        let menu = Menu::with_items(&[&application, &edit]).map_err(|error| error.to_string())?;
        menu.init_for_nsapp();
        Ok(Self {
            _menu: menu,
            edit,
            undo,
            redo,
            cut,
            copy,
            paste,
            select_all,
            locale,
        })
    }

    /// Relabels the menu only when the effective language differs from the
    /// installed one. The key equivalents and actions are not touched.
    pub(super) fn set_locale(&mut self, locale: Locale) {
        if locale == self.locale {
            return;
        }
        let Ok(text) = messages(locale) else {
            return;
        };
        self.edit.set_text(&text.edit);
        self.undo.set_text(&text.undo);
        self.redo.set_text(&text.redo);
        self.cut.set_text(&text.cut);
        self.copy.set_text(&text.copy);
        self.paste.set_text(&text.paste);
        self.select_all.set_text(&text.select_all);
        self.locale = locale;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_language_has_a_complete_menu_catalog() {
        let english = messages(Locale::EnUs).unwrap();
        let portuguese = messages(Locale::PtBr).unwrap();
        for text in [&english, &portuguese] {
            for label in [
                &text.edit,
                &text.undo,
                &text.redo,
                &text.cut,
                &text.copy,
                &text.paste,
                &text.select_all,
            ] {
                assert!(!label.trim().is_empty());
                // `muda` reads `&` as a mnemonic marker.
                assert!(!label.contains('&'));
            }
        }
        assert_ne!(english.paste, portuguese.paste);
    }

    #[test]
    fn catalog_keys_are_exactly_the_supported_locales() {
        let catalogs: BTreeMap<String, serde_json::Value> = serde_json::from_str(CATALOG).unwrap();
        let mut keys: Vec<_> = catalogs.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, [Locale::EnUs.code(), Locale::PtBr.code()]);
    }
}
