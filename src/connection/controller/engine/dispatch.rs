use super::*;

pub(super) fn dispatch<F: Factory>(
    request: Request,
    factory: &F,
    slots: &mut BTreeMap<String, Slot<'_>>,
    output: &mut VecDeque<Message>,
    interval: &ProbeClock,
    cleanup_capable: bool,
    failure_capable: bool,
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
    let (id, generation) = match &request.command {
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
            // No signature request can be pending in this slice: a reply is
            // an invalid command for the current state.
            fail(output, ErrorCode::InvalidRequest);
            return;
        }
        Command::Connect { id, generation, .. }
        | Command::Disconnect { id, generation }
        | Command::Probe { id, generation } => (id, *generation),
        Command::SetProbeInterval { .. } | Command::VerifyCleanup { .. } => unreachable!(),
    };
    let Some(slot) = slots.get_mut(id) else {
        fail(output, ErrorCode::ProfileNotFound);
        return;
    };
    if generation == 0
        || match request.command {
            Command::Probe { .. } => generation != slot.generation,
            _ => generation <= slot.generation,
        }
    {
        fail(output, ErrorCode::InvalidRequest);
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
            slot.cancel();
            slot.pending = None;
            slot.generation = generation;
            slot.failures = 0;
            slot.cleaning = false;
            slot.failure = None;
            slot.state = if slot.worker.is_some() {
                ConnectionState::Disconnecting
            } else {
                ConnectionState::Off
            };
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
