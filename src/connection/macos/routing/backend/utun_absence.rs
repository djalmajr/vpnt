//! Restricted re-export: the shared predicate moved to `vip::retired`.
//!
//! The Root route scope and the existing absence tests keep calling
//! `utun_absence::observed`; no logic remains here.
pub(super) use crate::connection::macos::vip::retired::observed;
