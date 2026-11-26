use super::*;
use crate::diagnostic_sink::{self, Sink};

#[cfg(target_os = "macos")]
pub(super) fn dispatch_sign_reply(
    request: Request,
    signers: Option<&RemoteSigners>,
    output: &mut VecDeque<Message>,
) -> Option<Request> {
    let Command::SignReply {
        id,
        profile,
        generation,
        epoch,
        result,
    } = request.command
    else {
        return Some(request);
    };
    let accepted = valid_profile_id(&request.id)
        && signers.is_some_and(|signers| signers.deliver(id, &profile, generation, epoch, result));
    output.push_back(if accepted {
        Message::Accepted { id: request.id }
    } else {
        Message::Failed {
            id: request.id,
            error: ErrorCode::InvalidRequest,
        }
    });
    None
}

pub(super) fn dispatch<F: Factory>(
    request: Request,
    factory: &F,
    slots: &mut BTreeMap<String, Slot<'_>>,
    output: &mut VecDeque<Message>,
    interval: &ProbeClock,
    cleanup_capable: bool,
    failure_capable: bool,
) {
    dispatch_with_diagnostics(
        request,
        factory,
        slots,
        output,
        interval,
        cleanup_capable,
        failure_capable,
        &mut &diagnostic_sink::ENGINE,
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "the diagnostic sink is independent of protocol output"
)]
pub(super) fn dispatch_with_diagnostics<F: Factory>(
    request: Request,
    factory: &F,
    slots: &mut BTreeMap<String, Slot<'_>>,
    output: &mut VecDeque<Message>,
    interval: &ProbeClock,
    cleanup_capable: bool,
    failure_capable: bool,
    diagnostics: &mut impl Sink,
) {
    let fail = |output: &mut VecDeque<_>, error| {
        output.push_back(Message::Failed {
            id: request.id.clone(),
            error,
        })
    };
    if !valid_profile_id(&request.id) {
        fail(output, ErrorCode::InvalidRequest);
        return;
    }
    if let Command::VerifyCleanup { profile } = &request.command {
        if !cleanup_capable {
            fail(output, ErrorCode::Unavailable);
            return;
        }
        let Some(slot) = slots.get(profile) else {
            fail(output, ErrorCode::ProfileNotFound);
            return;
        };
        // A queued or live attempt owns its own inventory. Recovery may only
        // examine this profile after its worker has finished and been joined.
        if slot.worker.is_some() || slot.pending.is_some() {
            fail(output, ErrorCode::ProfileBusy);
            return;
        }
        let _ = factory.verify_cleanup(&slot.profile);
        output.push_back(snapshot(request.id, factory, slots, true, failure_capable));
        return;
    }
    // A global cadence preference: no profile/slot lookup, no credential or
    // network authority. The handler only replaces shared durations in place.
    if let Command::SetProbeInterval {
        interval: requested,
    } = &request.command
    {
        interval.set(requested.duration());
        for slot in slots.values_mut() {
            slot.interval.set(requested.duration());
        }
        output.push_back(Message::Accepted { id: request.id });
        return;
    }
    let (command, id, generation) = match &request.command {
        Command::Diagnostics {} => {
            // The authenticated helper handles this before forwarding requests.
            fail(output, ErrorCode::Unavailable);
            return;
        }
        Command::Snapshot {} => {
            output.push_back(snapshot(
                request.id,
                factory,
                slots,
                cleanup_capable,
                failure_capable,
            ));
            return;
        }
        #[cfg(unix)]
        Command::SignReply { .. } => {
            // Platforms without a remote signer reject replies.
            fail(output, ErrorCode::InvalidRequest);
            return;
        }
        Command::Connect { id, generation, .. } => ("connect", id, *generation),
        Command::Disconnect { id, generation } => ("disconnect", id, *generation),
        Command::Probe { id, generation } => ("probe", id, *generation),
        Command::SetProbeInterval { .. } | Command::VerifyCleanup { .. } => unreachable!(),
    };
    let diagnostic_id = if valid_profile_id(id) {
        id.as_str()
    } else {
        "<invalid>"
    };
    let mut reject = |output: &mut VecDeque<_>, slot_generation: Option<u64>, error| {
        fail(output, error);
        let slot_generation =
            slot_generation.map_or_else(|| "none".into(), |value| value.to_string());
        diagnostics.record(format!(
            "vpnt-helper: engine: command={command} event=failed id={diagnostic_id} generation={generation} slot_generation={slot_generation} error={error:?}"
        ));
    };
    let Some(slot) = slots.get_mut(id) else {
        reject(output, None, ErrorCode::ProfileNotFound);
        return;
    };
    if generation == 0
        || match request.command {
            Command::Probe { .. } => generation != slot.generation,
            _ => generation <= slot.generation,
        }
    {
        reject(output, Some(slot.generation), ErrorCode::InvalidRequest);
        return;
    }
    match request.command {
        Command::Connect {
            interval: requested,
            credentials,
            ..
        } => {
            if factory.cleanup_blocked(&slot.profile) {
                fail(output, ErrorCode::ProfileBusy);
                return;
            }
            if !factory.supports(slot.profile.kind) {
                fail(output, ErrorCode::MissingProgram);
                return;
            }
            if credentials.validate(slot.profile.kind).is_err() {
                fail(output, ErrorCode::InvalidSecret);
                return;
            }
            let replacing = slot.worker.is_some();
            slot.cancel();
            // This generation's cadence; a later `SetProbeInterval` replaces it.
            slot.interval.set(requested.duration());
            slot.pending = Some(Pending {
                request: request.id.clone(),
                credentials,
            });
            slot.generation = generation;
            slot.failures = 0;
            slot.cleaning = false;
            // A new attempt clears the previous attempt's note.
            slot.failure = None;
            slot.state = if replacing {
                ConnectionState::Reconnecting
            } else {
                ConnectionState::Connecting
            };
        }
        Command::Disconnect { .. } => {
            let worker = slot.worker.is_some();
            slot.cancel();
            slot.pending = None;
            slot.generation = generation;
            slot.failures = 0;
            slot.cleaning = false;
            slot.failure = None;
            slot.state = if worker {
                ConnectionState::Disconnecting
            } else {
                ConnectionState::Off
            };
            diagnostics.record(format!(
                "vpnt-helper: engine: command=disconnect event=accepted id={diagnostic_id} generation={generation} worker={worker}"
            ));
        }
        Command::Probe { .. } => {
            if let Some(worker) = &slot.worker
                && worker.generation == generation
                && matches!(
                    slot.state,
                    ConnectionState::Verifying
                        | ConnectionState::Connected
                        | ConnectionState::Unresponsive
                )
            {
                worker.signals.probe.store(true, Ordering::Release);
            } else {
                fail(output, ErrorCode::ProfileBusy);
                return;
            }
        }
        #[cfg(unix)]
        Command::SignReply { .. } => unreachable!(),
        Command::Snapshot {}
        | Command::Diagnostics {}
        | Command::SetProbeInterval { .. }
        | Command::VerifyCleanup { .. } => {
            unreachable!()
        }
    }
    output.push_back(Message::Accepted { id: request.id });
    output.push_back(slot.changed(failure_capable));
}

fn snapshot<F: Factory>(
    id: String,
    factory: &F,
    slots: &BTreeMap<String, Slot<'_>>,
    cleanup_capable: bool,
    failure_capable: bool,
) -> Message {
    Message::Snapshot {
        id,
        protocol_version: VERSION,
        version: env!("CARGO_PKG_VERSION").into(),
        build: None,
        profiles: slots.values().map(|slot| slot.profile.clone()).collect(),
        connections: slots
            .values()
            .map(|slot| {
                let blocked = cleanup_capable && factory.cleanup_blocked(&slot.profile);
                TunnelStatus {
                    id: slot.profile.id.clone(),
                    generation: slot.generation,
                    state: if blocked {
                        ConnectionState::CleanupUnconfirmed
                    } else {
                        slot.state
                    },
                    failures: if blocked { 0 } else { slot.failures },
                    cleaning: if blocked { false } else { slot.cleaning },
                    failure: slot.failure.filter(|_| failure_capable && !blocked),
                }
            })
            .collect(),
    }
}
