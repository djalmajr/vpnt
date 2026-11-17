import { expect, test } from "bun:test";
import { commandFlow } from "./commandFlow";
import type { Command, Snapshot } from "./model";

function scenario() {
  const pending: {
    command: Command;
    resolve(snapshot: Snapshot): void;
    reject(error: Error): void;
  }[] = [];
  let current: Snapshot | undefined;
  let error: string | undefined;
  const flow = commandFlow(
    (command) =>
      new Promise((resolve, reject) => {
        pending.push({ command, resolve, reject });
      }),
    (snapshot) => {
      current = snapshot;
    },
    (code) => {
      error = code;
    },
  );
  const snapshot = (version: string): Snapshot => ({
    version,
    demo: true,
    helper: "installed",
    preferences: {
      interval: 10,
      notify: true,
      reconnect: false,
      startup: false,
    },
    vpns: [],
  });
  return {
    flow,
    pending,
    snapshot,
    current: () => current,
    error: () => error,
  };
}

test("a poll started before cancellation cannot restore the old snapshot or error", async () => {
  for (const reject of [false, true]) {
    const s = scenario();
    const old = s.flow.poll(() => true);
    const action = s.flow.run({ type: "toggle", id: "one" });
    s.pending[1].resolve(s.snapshot("cancelled"));
    expect(await action).toBe(true);
    if (reject) s.pending[0].reject(new Error("offline"));
    else s.pending[0].resolve(s.snapshot("old-connected"));
    await old;
    expect(s.current()?.version).toBe("cancelled");
    expect(s.error()).toBeUndefined();
  }
});

test("an earlier action cannot overwrite a newer action or authorize its navigation", async () => {
  for (const reject of [false, true]) {
    const s = scenario();
    const first = s.flow.run({ type: "toggle", id: "one" });
    const later = s.flow.run({ type: "disconnect_all" });
    s.pending[1].resolve(s.snapshot("off"));
    expect(await later).toBe(true);
    if (reject) s.pending[0].reject(new Error("invalid_name"));
    else s.pending[0].resolve(s.snapshot("previous"));
    expect(await first).toBe(false);
    expect(s.current()?.version).toBe("off");
    expect(s.error()).toBeUndefined();
  }
});

test("polling pauses for all pending actions and resumes after both success and failure", async () => {
  const s = scenario();
  const first = s.flow.run({ type: "toggle", id: "one" });
  const second = s.flow.run({ type: "toggle", id: "two" });
  const blocked = s.flow.poll(() => true);
  expect(s.pending).toHaveLength(2);
  await blocked;
  s.pending[1].reject(new Error("backend_unavailable"));
  expect(await second).toBe(false);
  expect(s.error()).toBe("backend_unavailable");
  const stillBlocked = s.flow.poll(() => true);
  expect(s.pending).toHaveLength(2);
  await stillBlocked;
  s.pending[0].resolve(s.snapshot("earlier"));
  expect(await first).toBe(false);
  const poll = s.flow.poll(() => true);
  expect(s.pending[2].command.type).toBe("get_snapshot");
  s.pending[2].resolve(s.snapshot("authoritative"));
  await poll;
  expect(s.current()?.version).toBe("authoritative");
});

test("disposed polling cannot affect the active page", async () => {
  for (const reject of [false, true]) {
    const s = scenario();
    let live = true;
    const poll = s.flow.poll(() => live);
    live = false;
    if (reject) s.pending[0].reject(new Error("offline"));
    else s.pending[0].resolve(s.snapshot("disposed"));
    await poll;
    expect(s.current()).toBeUndefined();
    expect(s.error()).toBeUndefined();
  }
});

test("a rejected stale reply is superseded and cannot own the newer action's banner", async () => {
  const s = scenario();
  const stale = s.flow.dispatch({
    type: "set_preferences",
    preferences: {
      interval: 30,
      notify: false,
      reconnect: true,
      startup: false,
    },
  });
  const newer = s.flow.dispatch({ type: "toggle", id: "one" });
  s.pending[1].reject(new Error("invalid_name"));
  expect(await newer).toEqual({
    ok: false,
    code: "invalid_name",
    superseded: false,
  });
  expect(s.error()).toBe("invalid_name");
  // The old preference command rejects late with a writable failure code.
  s.pending[0].reject(new Error("backend_unavailable"));
  expect(await stale).toEqual({
    ok: false,
    code: "backend_unavailable",
    superseded: true,
  });
  // The hook must not override the newer action's error for a stale reply.
  expect(s.error()).toBe("invalid_name");
});
