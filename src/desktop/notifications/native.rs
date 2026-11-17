//! `UNUserNotificationCenter` channel. No request or delivery happens on
//! construction; every send is driven by the shared decision kernel. Callbacks
//! capture only the kernel state and a zero-sized channel handle that fetches
//! the shared center on demand, so no native object crosses a queue.

use super::kernel::{self, Callback, Channel, Status};
use crate::notifications::Notice;
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNAuthorizationStatus, UNMutableNotificationContent,
    UNNotificationRequest, UNNotificationSettings, UNUserNotificationCenter,
};
use std::{
    ptr::NonNull,
    sync::{Arc, Mutex},
};

pub(super) fn send(notice: Notice) {
    kernel::send(notice, Arc::new(System));
}

/// The real channel. `currentNotificationCenter` is process-wide, so the value
/// itself holds nothing and stays safe to clone into callbacks.
struct System;

impl Channel for System {
    fn settings(&self, done: Callback<Status>) {
        // The kernel ignores repeated callbacks, so a duplicated native
        // delivery cannot turn into a second request or notification.
        // `RcBlock` needs `Fn`; the slot keeps the one-shot callback from being
        // consumed twice if the framework invokes the block again.
        let slot = Mutex::new(Some(done));
        let block = RcBlock::new(move |settings: NonNull<UNNotificationSettings>| {
            let callback = slot
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            let Some(mut done) = callback else {
                return;
            };
            // SAFETY: the framework passes a valid settings object for this callback.
            done(status(unsafe { settings.as_ref() }.authorizationStatus()));
        });
        UNUserNotificationCenter::currentNotificationCenter()
            .getNotificationSettingsWithCompletionHandler(&block);
    }

    fn authorize(&self, done: Callback<bool>) {
        let slot = Mutex::new(Some(done));
        let block = RcBlock::new(move |granted: Bool, _error: *mut NSError| {
            let callback = slot
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            let Some(mut done) = callback else {
                return;
            };
            done(granted.as_bool());
        });
        UNUserNotificationCenter::currentNotificationCenter()
            .requestAuthorizationWithOptions_completionHandler(
                UNAuthorizationOptions::Alert,
                &block,
            );
    }

    fn deliver(&self, notice: Notice) {
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let identifier = NSString::from_str(&notice.id);
        let content = UNMutableNotificationContent::new();
        let title = NSString::from_str(&notice.title);
        let body = NSString::from_str(&notice.body);
        content.setTitle(&title);
        content.setBody(&body);
        let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &identifier,
            &content,
            None,
        );
        center.addNotificationRequest_withCompletionHandler(&request, None);
    }
}

fn status(value: UNAuthorizationStatus) -> Status {
    if value == UNAuthorizationStatus::Authorized
        || value == UNAuthorizationStatus::Provisional
        || value == UNAuthorizationStatus::Ephemeral
    {
        Status::Authorized
    } else if value == UNAuthorizationStatus::NotDetermined {
        Status::NotDetermined
    } else if value == UNAuthorizationStatus::Denied {
        Status::Denied
    } else {
        Status::Unsupported
    }
}
