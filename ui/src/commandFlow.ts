import type { Command, Snapshot } from "./model";

/** Explicit result of one action. `superseded` means a newer action bumped the
 * revision, so the reply was dropped without committing its snapshot and
 * without owning the error banner; the host may still have applied it. A
 * refusal or timeout of the current action carries `code` and `superseded:
 * false`. */
export type RunResult =
  | { ok: true; snapshot: Snapshot }
  | { ok: false; code?: string; superseded: boolean };

export function commandFlow(
  invoke: (command: Command) => Promise<Snapshot>,
  receive: (snapshot: Snapshot) => void,
  fail: (code?: string) => void,
) {
  let running = 0;
  let revision = 0;
  const dispatch = async (command: Command): Promise<RunResult> => {
    const started = ++revision;
    fail();
    running += 1;
    try {
      const snapshot = await invoke(command);
      if (started !== revision) return { ok: false, superseded: true };
      receive(snapshot);
      return { ok: true, snapshot };
    } catch (error) {
      const code = error instanceof Error ? error.message : "error";
      // A rejected reply that arrives after a newer action started is stale:
      // the newer action owns the banner, so this reply must not set one and
      // must not be reported as a refusal of the current command.
      const superseded = started !== revision;
      if (!superseded) fail(code);
      return { ok: false, code, superseded };
    } finally {
      running -= 1;
    }
  };
  return {
    /** Boolean façade used by the screens; `dispatch` carries the detail. */
    run: async (command: Command): Promise<boolean> =>
      (await dispatch(command)).ok,
    dispatch,
    /** One read-only refresh of the authoritative state. It keeps the action
     * guards (paused while an action runs, dropped when a newer action starts)
     * but never bumps the revision itself, so refreshing cannot cancel a user
     * action. True only when the reply committed a new snapshot. */
    async poll(live: () => boolean): Promise<boolean> {
      if (running) return false;
      const started = revision;
      try {
        const snapshot = await invoke({ type: "get_snapshot" });
        if (!live() || started !== revision) return false;
        receive(snapshot);
        return true;
      } catch {
        if (live() && started === revision) fail("backend_unavailable");
        return false;
      }
    },
  };
}
