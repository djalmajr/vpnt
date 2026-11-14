import { expect, test } from "bun:test";
import type { Snapshot } from "./model";
import type { Route } from "./navigation";

// The hook module imports the bridge, which registers its reply channel on
// `window` at import time; the bridge itself is not exercised here. The stub
// exists only for that import and is removed again so it cannot leak into
// other test files sharing the process.
const scope = globalThis as unknown as { window?: unknown };
const previousWindow = scope.window;
scope.window = {};
const { reconcileRoute } = await import("./useAppState");
if (previousWindow === undefined) delete scope.window;
else scope.window = previousWindow;

const snapshot = (overrides: Partial<Snapshot> = {}): Snapshot => ({
  version: "0.1.0",
  demo: false,
  helper: "installed",
  preferences: { interval: 10, notify: true, reconnect: false, startup: false },
  vpns: [],
  ...overrides,
});

// Regression guard (no mutation campaign was run): the first-use screen kept
// offering Install because a later authoritative installation never
// reconciled the route it had derived from an earlier snapshot.
test("onboarding deixa de existir após confirmação tardia de instalado", () => {
  expect(reconcileRoute({ page: "onboarding" }, snapshot())).toEqual({
    page: "panel",
  });
});

// Regression guard (no mutation campaign was run): the snapshot must not
// navigate every route, which would discard explicit destinations and profile
// drafts.
test("rotas explícitas preservam a intenção do usuário", () => {
  const routes: Route[] = [
    { page: "preferences" },
    { page: "profile", kind: "ipsec" },
    { page: "profile", id: "p1" },
    { page: "log", id: "p1" },
    { page: "about" },
    { page: "new" },
    { page: "panel" },
  ];
  for (const route of routes)
    expect(reconcileRoute(route, snapshot())).toBe(route);
});

// Regression guard (no mutation campaign was run): demo snapshots are retained
// and marked and must never move the user, and a missing/outdated helper keeps
// onboarding offering its own action.
test("demo e helper ausente/desatualizado não redirecionam", () => {
  const onboarding: Route = { page: "onboarding" };
  expect(reconcileRoute(onboarding, snapshot({ demo: true }))).toBe(onboarding);
  expect(reconcileRoute(onboarding, snapshot({ helper: "missing" }))).toBe(
    onboarding,
  );
  expect(reconcileRoute(onboarding, snapshot({ helper: "outdated" }))).toBe(
    onboarding,
  );
});
