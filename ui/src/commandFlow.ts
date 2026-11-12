import type { Command, Snapshot } from "./model";

export function commandFlow(
  invoke: (command: Command) => Promise<Snapshot>,
  receive: (snapshot: Snapshot) => void,
  fail: (code?: string) => void,
) {
  let running = 0;
  let revision = 0;
  return {
    async run(command: Command) {
      const started = ++revision;
      fail();
      running += 1;
      try {
        const snapshot = await invoke(command);
        if (started !== revision) return false;
        receive(snapshot);
        return true;
      } catch (error) {
        if (started === revision)
          fail(error instanceof Error ? error.message : "error");
        return false;
      } finally {
        running -= 1;
      }
    },
    async poll(live: () => boolean) {
      if (running) return;
      const started = revision;
      try {
        const snapshot = await invoke({ type: "get_snapshot" });
        if (live() && started === revision) receive(snapshot);
      } catch {
        if (live() && started === revision) fail("backend_unavailable");
      }
    },
  };
}
