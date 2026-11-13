import type { RunResult } from "./commandFlow";
import type { NativePreferences } from "./model";

export type PreferencesPatch = Partial<NativePreferences>;

const fields = ["interval", "notify", "reconnect", "startup"] as const;

/** Compose the full document the bridge expects from the base the backend last
 * reported plus the fields the user actually changed. */
function compose(
  base: NativePreferences,
  change: PreferencesPatch,
): NativePreferences {
  return {
    interval: change.interval ?? base.interval,
    notify: change.notify ?? base.notify,
    reconnect: change.reconnect ?? base.reconnect,
    startup: change.startup ?? base.startup,
  };
}

/**
 * Serializes `set_preferences` commands and never holds optimistic state.
 *
 * - Every command carries a complete document, derived from the authoritative
 *   snapshot plus the still-unconfirmed user changes.
 * - Only one command is in flight. Changes made meanwhile stay queued and are
 *   merged into the next document, so a slow reply cannot erase a newer choice.
 * - A refused, timed-out or superseded reply is never resent. Before any newer
 *   queued change is composed, the flow asks for a fresh snapshot (`refresh`)
 *   and composes from what the host reports, never from the base captured
 *   before the command: the host may have applied the attempted document even
 *   when the reply was dropped or timed out.
 * - If the refresh does not commit, the queued change waits for the next
 *   received snapshot (`sync`), which the app calls on every receive. No timer
 *   or delay is involved.
 * - Nothing is sent before the first snapshot exists and the user changes
 *   something; the queued intent flushes on that first snapshot instead of
 *   being stranded.
 * - While not live (the screen is unmounted), queued - not yet started -
 *   changes are discarded, no new send or pending publication happens, and an
 *   in-flight host effect is left alone. `setLive` is driven by the hook's
 *   effect, so a StrictMode cleanup/setup cycle revives the same instance
 *   instead of poisoning it.
 */
export function createPreferencesFlow({
  authoritative,
  send,
  refresh,
  onPendingChange,
}: {
  authoritative: () => NativePreferences | undefined;
  send: (preferences: NativePreferences) => Promise<RunResult>;
  refresh: () => Promise<boolean>;
  onPendingChange?: (pending: boolean) => void;
}) {
  let queued: PreferencesPatch = {};
  let sending = false;
  let active: Promise<void> | undefined;
  let published = false;
  let live = true;

  const hasQueued = () => fields.some((field) => queued[field] !== undefined);

  function publish(force = false) {
    if (!live && !force) return;
    const next = live && (sending || hasQueued());
    if (next !== published) {
      published = next;
      onPendingChange?.(next);
    }
  }

  async function drain() {
    sending = true;
    publish();
    try {
      while (live && hasQueued()) {
        const base = authoritative();
        // No snapshot yet: keep the intent for the first received one.
        if (!base) return;
        const change = queued;
        queued = {};
        const result = await send(compose(base, change));
        // Disposed during the send: keep the host effect, send nothing else.
        if (!live) return;
        if (result.ok) continue;
        // Nothing newer to compose: stop without an extra round trip. `change`
        // itself is never resent.
        if (!hasQueued()) return;
        // Reconcile the base before composing the queued change: the host may
        // have applied the attempted document anyway (timeout) while the reply
        // was dropped or refused.
        if (!(await refresh())) return;
      }
    } finally {
      sending = false;
      publish();
    }
  }

  function start() {
    active ??= drain().finally(() => {
      active = undefined;
    });
    return active;
  }

  return {
    pending: () => live && (sending || hasQueued()),
    update(change: PreferencesPatch): Promise<void> {
      if (!live) return Promise.resolve();
      for (const field of fields) {
        const value = change[field];
        if (value !== undefined)
          (queued as Record<string, unknown>)[field] = value;
      }
      publish();
      return start();
    },
    /** A snapshot was received (action reply or poll): flush intent that still
     * waits for fresh authoritative state. */
    sync(): Promise<void> {
      return live && hasQueued() ? start() : Promise.resolve();
    },
    /** Lifecycle from the hook effect: false discards not-yet-started changes;
     * true (StrictMode re-setup) makes the reused instance usable again. */
    setLive(value: boolean) {
      live = value;
      if (!live) {
        queued = {};
        publish(true);
      }
    },
  };
}
