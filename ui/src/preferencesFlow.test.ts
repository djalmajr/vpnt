import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { commandFlow } from "./commandFlow";
import { Select, type T, Toggle } from "./components/common";
import { translate } from "./i18n";
import type { Command, NativePreferences, Snapshot } from "./model";
import { createPreferencesFlow } from "./preferencesFlow";
import { Preferences } from "./screens/Preferences";
import {
  defaultPreferences,
  loadSettings,
  preferencesDiff,
  type Settings,
  saveSettings,
} from "./settings";

type Call = {
  command: Command;
  resolve(snapshot: Snapshot): void;
  reject(error: Error): void;
};

/**
 * Real `commandFlow` with a deferred bridge, plus the same `receive → sync`
 * contract `useAppState` wires: every committed snapshot is authoritative and
 * wakes queued preference intent.
 */
function harness() {
  const calls: Call[] = [];
  let current: Snapshot | undefined;
  let error: string | undefined;
  let lastPending = false;
  const published: boolean[] = [];
  let sync: () => void = () => {};
  const flow = commandFlow(
    (command) =>
      new Promise<Snapshot>((resolve, reject) => {
        calls.push({ command, resolve, reject });
      }),
    (snapshot) => {
      current = snapshot;
      sync();
    },
    (code) => {
      error = code;
    },
  );
  const prefs = createPreferencesFlow({
    authoritative: () => current?.preferences,
    send: (preferences) =>
      flow.dispatch({ type: "set_preferences", preferences }),
    refresh: () => flow.poll(() => true),
    onPendingChange: (value) => {
      lastPending = value;
      published.push(value);
    },
  });
  sync = () => {
    void prefs.sync();
  };
  const snapshot = (
    preferences: NativePreferences,
    version = "snapshot",
  ): Snapshot => ({
    version,
    demo: true,
    helper: "installed",
    preferences,
    vpns: [],
  });
  const loaded = async () => {
    const poll = flow.poll(() => true);
    calls[0].resolve(snapshot(defaultPreferences, "initial"));
    await poll;
  };
  const sent = () =>
    calls.filter((call) => call.command.type === "set_preferences");
  const documents = () =>
    sent().map(
      (call) =>
        (call.command as Extract<Command, { type: "set_preferences" }>)
          .preferences,
    );
  return {
    calls,
    flow,
    prefs,
    snapshot,
    loaded,
    sent,
    documents,
    current: () => current,
    error: () => error,
    pendingFlag: () => lastPending,
    published,
  };
}

/** Lets the flow's promise chain advance without awaiting a reply that has not
 * landed yet (the drain stays suspended on the deferred bridge call). */
const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const settingsWith = (preferences: NativePreferences): Settings => ({
  locale: "system",
  theme: "system",
  ...preferences,
});

describe("preferências nativas da UI", () => {
  // Mutation captured: wiring the flow at mount replays or writes preferences without the user.
  test("montar a tela não envia nem grava preferências nativas", async () => {
    const s = harness();
    await s.loaded();
    expect(s.sent()).toHaveLength(0);
    expect(s.prefs.pending()).toBe(false);
    expect(s.current()?.preferences).toEqual(defaultPreferences);
  });

  // Mutation captured: dropping the queued intent when no base exists strands the change forever.
  test("intenção anterior ao primeiro snapshot é enviada quando ele chega", async () => {
    const s = harness();
    const done = s.prefs.update({ interval: 30 });
    expect(s.calls).toHaveLength(0);
    expect(s.prefs.pending()).toBe(true);
    expect(s.pendingFlag()).toBe(true);
    await done;
    const poll = s.flow.poll(() => true);
    s.calls[0].resolve(s.snapshot(defaultPreferences, "first"));
    await poll;
    // receive → sync → exactly one command, derived from that first snapshot
    expect(s.sent()).toHaveLength(1);
    expect(s.documents()[0]).toEqual({ ...defaultPreferences, interval: 30 });
    s.sent()[0].resolve(s.snapshot({ ...defaultPreferences, interval: 30 }));
    await flush();
    expect(s.prefs.pending()).toBe(false);
    expect(s.pendingFlag()).toBe(false);
  });

  // Mutation captured: sending a partial document, or committing an optimist value before the reply.
  test("uma mudança emite um único comando tipado com o documento completo", async () => {
    const s = harness();
    await s.loaded();
    const done = s.prefs.update({ notify: false });
    expect(s.sent()).toHaveLength(1);
    expect(s.sent()[0].command).toEqual({
      type: "set_preferences",
      preferences: { ...defaultPreferences, notify: false },
    });
    expect(s.current()?.preferences).toEqual(defaultPreferences);
    const replied = { ...defaultPreferences, notify: false };
    s.sent()[0].resolve(s.snapshot(replied));
    await done;
    expect(s.current()?.preferences).toEqual(replied);
    expect(s.sent()).toHaveLength(1);
    expect(s.prefs.pending()).toBe(false);
  });

  // Mutation captured: keeping the requested value after a refusal invents a successful write.
  test("recusa mantém os valores anteriores e a mensagem do backend", async () => {
    for (const code of [
      "startup_unavailable",
      "startup_requires_approval",
      "preferences_unavailable",
    ]) {
      const s = harness();
      await s.loaded();
      const done = s.prefs.update({ startup: true });
      s.sent()[0].reject(new Error(code));
      await done;
      expect(s.current()?.preferences).toEqual(defaultPreferences);
      expect(s.error()).toBe(code);
      expect(s.sent()).toHaveLength(1);
      expect(s.prefs.pending()).toBe(false);
      // Nothing queued: no reconciliation round trip after a plain refusal.
      expect(
        s.calls.filter((call) => call.command.type === "get_snapshot"),
      ).toHaveLength(1);
    }
  });

  // Mutation captured: composing the queued change from the base captured before a superseded reply reverts the field the host accepted.
  test("resposta superseded não recompõe a partir da base antiga", async () => {
    const s = harness();
    await s.loaded();
    const first = s.prefs.update({ interval: 30 });
    expect(s.sent()).toHaveLength(1);
    s.prefs.update({ notify: false });
    const other = s.flow.run({ type: "toggle", id: "one" });
    // The superseding snapshot predates the host applying interval 30.
    s.calls[2].resolve(s.snapshot(defaultPreferences, "supersede"));
    expect(await other).toBe(true);
    // The dropped preference reply arrives late and is not committed.
    s.calls[1].resolve(
      s.snapshot({ ...defaultPreferences, interval: 30 }, "dropped"),
    );
    await flush();
    expect(s.sent()).toHaveLength(1);
    expect(s.calls[3].command.type).toBe("get_snapshot");
    s.calls[3].resolve(
      s.snapshot({ ...defaultPreferences, interval: 30 }, "reconciled"),
    );
    await flush();
    expect(s.sent()).toHaveLength(2);
    expect(s.documents()[1]).toEqual({
      ...defaultPreferences,
      interval: 30,
      notify: false,
    });
    // No composed document ever reverted the host's interval to 10.
    expect(s.documents().every((document) => document.interval === 30)).toBe(
      true,
    );
    s.sent()[1].resolve(
      s.snapshot({ ...defaultPreferences, interval: 30, notify: false }),
    );
    await first;
    expect(s.prefs.pending()).toBe(false);
  });

  // Mutation captured: composing after a timeout from the pre-command base erases the effect the host applied anyway.
  test("timeout recompõe sobre o estado real do Host, não sobre a base enviada", async () => {
    const s = harness();
    await s.loaded();
    const first = s.prefs.update({ interval: 30 });
    s.prefs.update({ notify: false });
    s.calls[1].reject(new Error("backend_unavailable"));
    await flush();
    expect(s.sent()).toHaveLength(1);
    expect(s.error()).toBe("backend_unavailable");
    // Explicit fresh snapshot instead of the stale base.
    expect(s.calls[2].command.type).toBe("get_snapshot");
    s.calls[2].resolve(
      s.snapshot(
        { ...defaultPreferences, interval: 30 },
        "applied-after-timeout",
      ),
    );
    await flush();
    expect(s.sent()).toHaveLength(2);
    expect(s.documents()[1]).toEqual({
      ...defaultPreferences,
      interval: 30,
      notify: false,
    });
    s.sent()[1].resolve(
      s.snapshot({ ...defaultPreferences, interval: 30, notify: false }),
    );
    await first;
  });

  // Mutation captured: resending the refused document (or composing it again) after a refusal.
  test("recusa não reenvia o documento recusado antes de recompor", async () => {
    const s = harness();
    await s.loaded();
    const first = s.prefs.update({ startup: true });
    s.prefs.update({ notify: false });
    s.calls[1].reject(new Error("startup_unavailable"));
    await flush();
    expect(s.sent()).toHaveLength(1);
    expect(s.calls[2].command.type).toBe("get_snapshot");
    s.calls[2].resolve(s.snapshot(defaultPreferences, "refused"));
    await flush();
    expect(s.sent()).toHaveLength(2);
    expect(s.documents()[1]).toEqual({
      ...defaultPreferences,
      notify: false,
    });
    expect(s.documents().filter((document) => document.startup)).toHaveLength(
      1,
    );
    s.sent()[1].resolve(s.snapshot({ ...defaultPreferences, notify: false }));
    await first;
  });

  // Mutation captured: composing after a failed refresh, instead of waiting for a received snapshot.
  test("refresh que não commita mantém a intenção até o próximo snapshot", async () => {
    const s = harness();
    await s.loaded();
    const first = s.prefs.update({ interval: 30 });
    s.prefs.update({ notify: false });
    s.calls[1].reject(new Error("backend_unavailable"));
    await flush();
    expect(s.calls[2].command.type).toBe("get_snapshot");
    s.calls[2].reject(new Error("backend_unavailable"));
    await flush();
    // Still exactly the attempted document: nothing is composed on a base that
    // could not be reconciled.
    expect(s.sent()).toHaveLength(1);
    expect(s.pendingFlag()).toBe(true);
    await first;
    // A later poll delivers the host's real state; receive → sync flushes.
    const poll = s.flow.poll(() => true);
    s.calls[3].resolve(
      s.snapshot({ ...defaultPreferences, interval: 30 }, "later"),
    );
    await poll;
    expect(s.sent()).toHaveLength(2);
    expect(s.documents()[1]).toEqual({
      ...defaultPreferences,
      interval: 30,
      notify: false,
    });
    s.sent()[1].resolve(
      s.snapshot({ ...defaultPreferences, interval: 30, notify: false }),
    );
    await flush();
    expect(s.pendingFlag()).toBe(false);
  });

  // Mutation captured: a stale poll committing after a preference change restores the old choice.
  test("uma resposta antiga de poll não restaura a escolha anterior", async () => {
    const s = harness();
    await s.loaded();
    const stale = s.flow.poll(() => true);
    const done = s.prefs.update({ interval: 30 });
    const chosen = { ...defaultPreferences, interval: 30 as const };
    s.sent()[0].resolve(s.snapshot(chosen, "chosen"));
    await done;
    s.calls[1].resolve(s.snapshot(defaultPreferences, "stale"));
    await stale;
    expect(s.current()?.preferences).toEqual(chosen);
    expect(s.error()).toBeUndefined();
  });

  // Mutation captured: routing locale/theme through the native document writes OS preferences for a local choice.
  test("idioma e tema permanecem locais e não viram comando", () => {
    const base = settingsWith(defaultPreferences);
    expect(preferencesDiff(base, { ...base, locale: "pt-BR" })).toEqual({});
    expect(preferencesDiff(base, { ...base, theme: "dark" })).toEqual({});
    expect(preferencesDiff(base, base)).toEqual({});
    expect(preferencesDiff(base, { ...base, interval: 60 })).toEqual({
      interval: 60,
    });
    expect(preferencesDiff(base, { ...base, startup: true })).toEqual({
      startup: true,
    });
  });

  // Mutation captured: restoring native fields from local storage replays a cached choice on load.
  test("preferências nativas antigas no armazenamento local não são replicadas", () => {
    const store = new Map<string, string>();
    const original = globalThis.localStorage;
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => store.get(key) ?? null,
        setItem: (key: string, value: string) => void store.set(key, value),
      },
    });
    try {
      store.set(
        "vpnt.preferences.v1",
        JSON.stringify({
          locale: "pt-BR",
          theme: "dark",
          interval: 60,
          notify: false,
          reconnect: true,
          startup: true,
        }),
      );
      expect(loadSettings()).toEqual({ locale: "pt-BR", theme: "dark" });
      saveSettings({ locale: "en-US", theme: "light" });
      expect(JSON.parse(store.get("vpnt.preferences.v1") ?? "{}")).toEqual({
        locale: "en-US",
        theme: "light",
      });
    } finally {
      Object.defineProperty(globalThis, "localStorage", {
        configurable: true,
        value: original,
      });
    }
  });

  // Mutation captured: a pending native write dimmed every switch, so the whole
  // row blinked 100→45→100% while the host answered. Busy keeps native
  // blocking and the authoritative checked state without the disabled paint.
  test("interruptor pendente bloqueia sem atenuar; desabilitado permanente mantém o dim", () => {
    const markup = (props: { disabled?: boolean; busy?: boolean }) =>
      renderToStaticMarkup(
        createElement(Toggle, {
          label: "notify",
          checked: true,
          onChange: () => {},
          ...props,
        }),
      );
    const busy = markup({ busy: true });
    expect(busy).toContain("disabled");
    expect(busy).toContain('aria-busy="true"');
    expect(busy).toContain('aria-checked="true"');
    expect(busy).not.toContain("dim");
    expect(busy).not.toMatch(/\sbusy=/);
    const permanent = markup({ disabled: true });
    expect(permanent).toContain("disabled");
    expect(permanent).toContain("dim");
    expect(permanent).not.toContain("aria-busy");
    // The permanent reason wins: a disabled+busy control stays unavailable.
    const both = markup({ disabled: true, busy: true });
    expect(both).toContain("disabled");
    expect(both).toContain('aria-busy="true"');
    expect(both).toContain("dim");
    const idle = markup({});
    expect(idle).not.toContain("disabled");
    expect(idle).not.toContain("dim");
    expect(idle).not.toContain("aria-busy");
    expect(idle).toContain('aria-checked="true"');
  });

  // Mutation captured: a pending interval write grayed the native select and
  // dimmed its wrapper, so the control flashed unavailable on every write.
  test("select pendente bloqueia sem trocar a pintura; permanente mantém o contrato", () => {
    const markup = (props: {
      disabled?: boolean;
      busy?: boolean;
      "aria-busy"?: boolean;
    }) =>
      renderToStaticMarkup(
        createElement(
          Select,
          { "aria-label": "interval", ...props },
          createElement("option", { value: 30 }, "30 s"),
        ),
      );
    const busy = markup({ busy: true });
    expect(busy).toContain('aria-busy="true"');
    expect(busy).toContain("select-control busy");
    expect(busy).toContain("disabled");
    expect(busy).not.toMatch(/\sbusy=/);
    const permanent = markup({ disabled: true });
    expect(permanent).toContain("disabled");
    expect(permanent).not.toContain("select-control busy");
    expect(permanent).not.toContain("aria-busy");
    // The permanent reason wins over the transient one.
    const both = markup({ disabled: true, busy: true });
    expect(both).toContain('aria-busy="true"');
    expect(both).not.toContain("select-control busy");
    // A caller-provided aria-busy survives when the control is idle.
    const callerBusy = markup({ "aria-busy": true });
    expect(callerBusy).toContain('aria-busy="true"');
    expect(callerBusy).not.toContain("disabled");
    const idle = markup({});
    expect(idle).toContain('aria-label="interval"');
    expect(idle).toContain('<option value="30">30 s</option>');
    expect(idle).not.toContain("disabled");
    expect(idle).not.toContain("aria-busy");
    expect(idle).not.toContain("busy");
  });

  // Mutation captured: Preferences passed `disabled` for a pending write, so
  // the whole preference form blinked instead of only blocking the controls.
  test("a tela de preferências usa busy pendente e mantém idioma/tema locais ativos", () => {
    const t: T = (key, values) => translate("pt-BR", key, values);
    const screen = (preferencesPending: boolean) =>
      renderToStaticMarkup(
        createElement(Preferences, {
          snapshot: {
            version: "snapshot",
            demo: true,
            helper: "installed",
            preferences: defaultPreferences,
            vpns: [],
          },
          settings: { ...settingsWith(defaultPreferences), preferencesPending },
          update: () => {},
          navigate: () => {},
          removeComponent: () => {},
          t,
        }),
      );
    const busy = screen(true);
    // Three switches plus the interval select wait on the host; the locale and
    // theme selects stay local and enabled.
    expect(busy.match(/aria-busy="true"/g)).toHaveLength(4);
    expect(busy.match(/ disabled/g)).toHaveLength(4);
    expect(busy).toContain("select-control busy");
    expect(busy).not.toContain("dim");
    const idle = screen(false);
    expect(idle).not.toContain("aria-busy");
    expect(idle).not.toContain(" disabled");
    expect(idle).not.toContain("busy");
  });

  // Mutation captured: a disposed flow still starts the queued second write.
  test("desmontar durante o primeiro envio descarta a segunda mudança", async () => {
    const s = harness();
    await s.loaded();
    const first = s.prefs.update({ interval: 30 });
    s.prefs.update({ notify: false });
    expect(s.prefs.pending()).toBe(true);
    const before = s.published.length;
    s.prefs.setLive(false);
    expect(s.prefs.pending()).toBe(false);
    expect(s.published.slice(before)).toEqual([false]);
    // The in-flight host effect completes, but nothing else is sent.
    s.calls[1].resolve(s.snapshot({ ...defaultPreferences, interval: 30 }));
    await first;
    expect(s.sent()).toHaveLength(1);
    expect(s.published.slice(before)).toEqual([false]);
  });

  // Mutation captured: a disposed flow composes and sends after the reconcile refresh returns.
  test("desmontar durante o refresh não compõe a mudança enfileirada", async () => {
    const s = harness();
    await s.loaded();
    const first = s.prefs.update({ interval: 30 });
    s.prefs.update({ notify: false });
    s.calls[1].reject(new Error("backend_unavailable"));
    await flush();
    expect(s.calls[2].command.type).toBe("get_snapshot");
    const before = s.published.length;
    s.prefs.setLive(false);
    expect(s.prefs.pending()).toBe(false);
    expect(s.published.slice(before)).toEqual([false]);
    s.calls[2].resolve(
      s.snapshot({ ...defaultPreferences, interval: 30 }, "late"),
    );
    await first;
    expect(s.sent()).toHaveLength(1);
    expect(s.published.slice(before)).toEqual([false]);
  });

  // Mutation captured: a StrictMode cleanup leaves `live` false forever, so the reused flow never writes again.
  test("cleanup e setup do StrictMode reativam a mesma instância", async () => {
    const s = harness();
    await s.loaded();
    s.prefs.setLive(false);
    s.prefs.setLive(true);
    const done = s.prefs.update({ notify: false });
    expect(s.sent()).toHaveLength(1);
    s.sent()[0].resolve(s.snapshot({ ...defaultPreferences, notify: false }));
    await done;
    expect(s.prefs.pending()).toBe(false);
  });

  // Mutation captured: leaving a write failure untranslated shows the raw host code to the user.
  test("os códigos de erro do Host têm texto nos dois idiomas", () => {
    const keys = [
      "preferencesUnavailable",
      "preferencesNotConfirmed",
      "startupRequiresApproval",
      "startupUnavailable",
    ] as const;
    for (const key of keys)
      for (const locale of ["pt-BR", "en-US"] as const) {
        const text = translate(locale, key);
        expect(text).not.toBe(key);
        expect(text.length).toBeGreaterThan(10);
      }
  });
});
