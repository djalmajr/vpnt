use super::*;

pub(super) fn dispatch(
    request: Request,
    slots: &mut BTreeMap<String, Slot<'_>>,
    output: &mut VecDeque<Message>,
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
    let (id, generation) = match &request.command {
        Command::Snapshot {} => {
            output.push_back(Message::Snapshot {
                id: request.id,
                protocol_version: VERSION,
                version: env!("CARGO_PKG_VERSION").into(),
                profiles: slots.values().map(|slot| slot.profile.clone()).collect(),
                connections: slots
                    .values()
                    .map(|slot| TunnelStatus {
                        id: slot.profile.id.clone(),
                        generation: slot.generation,
                        state: slot.state,
                    })
                    .collect(),
            });
            return;
        }
        Command::Connect { id, generation, .. }
        | Command::Disconnect { id, generation }
        | Command::Probe { id, generation } => (id, *generation),
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
        Command::Connect { credentials, .. } => {
            if slot.profile.kind != VpnKind::Ssl {
                fail(output, ErrorCode::MissingProgram);
                return;
            }
            if credentials.validate(VpnKind::Ssl).is_err() {
                fail(output, ErrorCode::InvalidSecret);
                return;
            }
            let replacing = slot.worker.is_some();
            slot.cancel();
            slot.pending = Some(Pending {
                request: request.id.clone(),
                credentials,
            });
            slot.generation = generation;
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
        Command::Snapshot {} => unreachable!(),
    }
    output.push_back(Message::Accepted { id: request.id });
    output.push_back(slot.changed());
}
