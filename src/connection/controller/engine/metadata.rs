use super::*;

pub(super) fn map(profiles: Vec<Profile>) -> Result<BTreeMap<String, Profile>, ErrorCode> {
    if profiles.len() > 64 || profiles.iter().any(|p| p.validate().is_err()) {
        return Err(ErrorCode::UntrustedConfiguration);
    }
    let count = profiles.len();
    let next: BTreeMap<_, _> = profiles.into_iter().map(|p| (p.id.clone(), p)).collect();
    if count != next.len() {
        return Err(ErrorCode::UntrustedConfiguration);
    }
    Ok(next)
}
pub(super) fn refresh(
    slots: &mut BTreeMap<String, Slot<'_>>,
    profiles: Vec<Profile>,
) -> Result<(), ErrorCode> {
    let next = map(profiles)?;
    // Validate the complete replacement before touching even an idle slot.
    for (id, slot) in slots.iter() {
        if next.get(id) == Some(&slot.profile) {
            continue;
        }
        if slot.worker.is_some() || slot.pending.is_some() {
            return Err(ErrorCode::ProfileBusy);
        }
        if next.contains_key(id) && slot.generation == u64::MAX {
            return Err(ErrorCode::Unavailable);
        }
    }
    slots.retain(|id, _| next.contains_key(id));
    for (id, profile) in next {
        if let Some(slot) = slots.get_mut(&id) {
            if profile != slot.profile {
                slot.profile = profile;
                slot.generation += 1;
                slot.state = ConnectionState::Off;
            }
        } else {
            slots.insert(
                id,
                Slot {
                    profile,
                    generation: 0,
                    state: ConnectionState::Off,
                    worker: None,
                    pending: None,
                },
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn slot(generation: u64, pending: bool) -> Slot<'static> {
        let profile:Profile=serde_json::from_value(serde_json::json!({"id":"one","name":"Original","kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap();
        Slot {
            profile,
            generation,
            state: if pending {
                ConnectionState::Connecting
            } else {
                ConnectionState::Off
            },
            worker: None,
            pending: pending.then(|| Pending {
                request: "pending".into(),
                credentials: Credentials {
                    password: "fictional".into(),
                    psk: "".into(),
                },
            }),
        }
    }
    #[test]
    fn a_queued_connection_protects_its_profile_before_the_worker_is_launched() {
        let slot = slot(1, true);
        let original = slot.profile.clone();
        let mut changed = original.clone();
        changed.gateway = "changed.example.test".into();
        let mut slots = BTreeMap::from([("one".into(), slot)]);
        assert!(matches!(
            refresh(&mut slots, vec![changed]),
            Err(ErrorCode::ProfileBusy)
        ));
        assert!(matches!(
            refresh(&mut slots, vec![]),
            Err(ErrorCode::ProfileBusy)
        ));
        assert_eq!(slots["one"].profile, original);
        assert_eq!(slots["one"].generation, 1);
        assert!(slots["one"].pending.is_some());
    }
    #[test]
    fn metadata_cannot_wrap_a_generation_or_partially_commit_an_overflow() {
        let mut slots = BTreeMap::from([("one".into(), slot(u64::MAX, false))]);
        let mut changed = slots["one"].profile.clone();
        changed.name = "Changed".into();
        assert!(matches!(
            refresh(&mut slots, vec![changed.clone()]),
            Err(ErrorCode::Unavailable)
        ));
        assert_eq!(slots["one"].profile.name, "Original");
        assert_eq!(slots["one"].generation, u64::MAX);
        slots.get_mut("one").unwrap().generation = u64::MAX - 1;
        refresh(&mut slots, vec![changed]).unwrap();
        assert_eq!(slots["one"].generation, u64::MAX);
    }
}
