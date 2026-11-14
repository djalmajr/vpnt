use super::*;
use crate::preferences::ProbeInterval;

// Mutation: exempting SetPreferences from the component-busy gate lets a choice
// change while an install/removal owns the runtime and its own child.
#[test]
fn preferences_are_refused_while_a_component_operation_is_live() {
    let mut h = Harness::new("flow", HELD);
    h.begin(Command::InstallHelper {}, 3);
    wait(|| {
        h.broker.poll();
        h.root.join("started").exists()
    });
    let before = h.broker.snapshot().preferences;
    let chosen = Preferences {
        interval: ProbeInterval::SIXTY,
        notify: true,
        reconnect: true,
        startup: false,
    };
    assert_eq!(
        h.broker
            .dispatch(
                Command::SetPreferences {
                    preferences: chosen
                },
                Instant::now() + Duration::from_secs(1)
            )
            .err(),
        Some("component_busy")
    );
    assert_eq!(h.broker.snapshot().preferences, before);
    // The live operation and its own child still finish normally afterwards.
    h.release();
    let (_, done) = h.result();
    assert!(done.is_ok(), "component result: {done:?}");
    assert!(h.root.join("finished").exists());
    wait(|| {
        h.broker.poll();
        !h.broker.component_busy()
    });
}
