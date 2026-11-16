import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { GlobalRegistrator } from "@happy-dom/global-registrator";
import { act, createElement } from "react";
import type { Root } from "react-dom/client";
import { type Locale, type MessageKey, translate } from "./i18n";
import type { Command, Snapshot, VpnView } from "./model";
import { defaultPreferences } from "./settings";

let App: typeof import("./App").App;
let createRoot: typeof import("react-dom/client").createRoot;
let root: Root | undefined;
let container: HTMLDivElement | undefined;
let originalFetch: typeof fetch;
let commands: Command[];
let snapshot: Snapshot;
const scope = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};
const previousActEnvironment = scope.IS_REACT_ACT_ENVIRONMENT;
/* The registrator only restores what it registered itself: it skips its own
   Symbol properties and anything the app adds through window (the bridge's
   reply callback). Snapshot every own key and put the global back exactly. */
const ownKeys = (): (string | symbol)[] => Reflect.ownKeys(globalThis);
let globalsBefore: Map<string | symbol, PropertyDescriptor | undefined>;
function restoreGlobals() {
  for (const key of ownKeys()) {
    if (!globalsBefore.has(key)) Reflect.deleteProperty(globalThis, key);
  }
  for (const [key, descriptor] of globalsBefore) {
    const current = Reflect.getOwnPropertyDescriptor(globalThis, key);
    if (descriptor && current !== descriptor)
      Reflect.defineProperty(globalThis, key, descriptor);
  }
}

const vpn: VpnView = {
  profile: {
    id: "profile-fixture",
    name: "Fixture VPN",
    kind: "ipsec",
    gateway: "vpn.example.test",
    username: "fixture",
    networks: [],
    port: 500,
    certificate: "",
    probeHost: "192.0.2.1",
    probePort: 8443,
    probeMethod: "tcp",
  },
  state: "off",
  cleaning: false,
  hasPassword: false,
  hasPsk: false,
  log: [],
};

beforeAll(async () => {
  globalsBefore = new Map(
    ownKeys().map((key) => [
      key,
      Reflect.getOwnPropertyDescriptor(globalThis, key),
    ]),
  );
  GlobalRegistrator.register({ url: "http://localhost/" });
  scope.IS_REACT_ACT_ENVIRONMENT = true;
  originalFetch = globalThis.fetch;
  ({ createRoot } = await import("react-dom/client"));
  ({ App } = await import("./App"));
});
afterEach(async () => {
  try {
    if (root) await act(async () => root?.unmount());
  } finally {
    root = undefined;
    container?.remove();
    container = undefined;
    globalThis.fetch = originalFetch;
    localStorage.clear();
  }
});
afterAll(async () => {
  try {
    if (previousActEnvironment === undefined)
      delete scope.IS_REACT_ACT_ENVIRONMENT;
    else scope.IS_REACT_ACT_ENVIRONMENT = previousActEnvironment;
    await GlobalRegistrator.unregister();
  } finally {
    restoreGlobals();
  }
  const leaked = ownKeys().filter((key) => !globalsBefore.has(key));
  expect(leaked.map(String)).toEqual([]);
  expect(Reflect.getOwnPropertyDescriptor(globalThis, "__vpntReply")).toEqual(
    globalsBefore.get("__vpntReply"),
  );
});

async function mount(locale: Locale, missing = false) {
  commands = [];
  snapshot = {
    version: "0.1.0",
    demo: false,
    helper: missing ? "missing" : "installed",
    preferences: defaultPreferences,
    vpns: missing ? [] : [vpn],
  };
  localStorage.setItem(
    "vpnt.preferences.v1",
    JSON.stringify({ locale, theme: "light" }),
  );
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as {
      id: string;
      command: Command;
    };
    const command = request.command;
    commands.push(command);
    if (command.type === "save_profile")
      snapshot = { ...snapshot, vpns: [{ ...vpn, profile: command.profile }] };
    if (command.type === "remove_profile") snapshot = { ...snapshot, vpns: [] };
    if (command.type === "install_helper")
      snapshot = { ...snapshot, helper: "installed" };
    return new Response(JSON.stringify({ id: request.id, snapshot }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
  container = document.createElement("div");
  container.id = "root";
  document.body.append(container);
  root = createRoot(container);
  await act(async () => {
    root?.render(createElement(App));
  });
}

const t = (
  locale: Locale,
  key: MessageKey,
  values?: Record<string, string | number>,
) => translate(locale, key, values);
function byLabel(label: string): HTMLButtonElement {
  const button = [
    ...document.querySelectorAll<HTMLButtonElement>("button"),
  ].find((item) => item.getAttribute("aria-label") === label);
  if (!button) throw new Error(`Button with label ${label} not found`);
  return button;
}
function byText(
  text: string,
  parent: ParentNode = document,
): HTMLButtonElement {
  const button = [...parent.querySelectorAll<HTMLButtonElement>("button")].find(
    (item) => item.textContent?.trim() === text,
  );
  if (!button) throw new Error(`Button ${text} not found`);
  return button;
}
async function click(element: HTMLElement) {
  await act(async () => element.click());
}
function heading(): string | undefined {
  return document.querySelector("h1")?.textContent ?? undefined;
}
function dialog(locale: Locale, key: MessageKey): HTMLDialogElement | null {
  return (
    [...document.querySelectorAll("dialog")].find(
      (item) => item.getAttribute("aria-label") === t(locale, key),
    ) ?? null
  );
}
function input(locale: Locale, key: MessageKey): HTMLInputElement {
  const label = [
    ...document.querySelectorAll<HTMLLabelElement>("label.field"),
  ].find((item) => item.querySelector("span")?.textContent === t(locale, key));
  const element = label?.querySelector("input");
  if (!element) throw new Error(`Input ${key} not found`);
  return element;
}
async function edit(locale: Locale, key: MessageKey, value: string) {
  const element = input(locale, key);
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set;
  if (!setter) throw new Error("Native value setter missing");
  await act(async () => {
    setter.call(element, value);
    element.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
async function openProfile(locale: Locale, origin: "home" | "preferences") {
  if (origin === "preferences") {
    await click(byLabel(t(locale, "preferences")));
    expect(heading()).toBe(t(locale, "preferences"));
    await click(byText(vpn.profile.name + t(locale, "ipsec")));
  } else
    await click(
      byLabel(t(locale, "profileDetails", { name: vpn.profile.name })),
    );
  expect(heading()).toBe(vpn.profile.name);
  expect(document.querySelector("form.profile-form")).not.toBeNull();
}
function destination(locale: Locale, origin: "home" | "preferences") {
  expect(heading()).toBe(t(locale, origin === "home" ? "vpns" : "preferences"));
  expect(document.querySelector("form.profile-form")).toBeNull();
  expect(dialog(locale, "discardTitle")).toBeNull();
}
const actions = () =>
  commands.filter((command) => command.type !== "get_snapshot");

for (const locale of ["pt-BR", "en-US"] as const) {
  for (const origin of ["home", "preferences"] as const) {
    test(`${locale} ${origin}: voltar limpo`, async () => {
      await mount(locale);
      await openProfile(locale, origin);
      await click(byLabel(t(locale, "back")));
      destination(locale, origin);
      expect(actions()).toEqual([]);
    });
    test(`${locale} ${origin}: manter edição e descartar ao voltar`, async () => {
      await mount(locale);
      await openProfile(locale, origin);
      await edit(locale, "name", "Edited fixture");
      await click(byLabel(t(locale, "back")));
      expect(dialog(locale, "discardTitle")).not.toBeNull();
      await click(byText(t(locale, "keepEditing")));
      expect(dialog(locale, "discardTitle")).toBeNull();
      expect(input(locale, "name").value).toBe("Edited fixture");
      await click(byLabel(t(locale, "back")));
      expect(dialog(locale, "discardTitle")).not.toBeNull();
      await click(byText(t(locale, "discard")));
      destination(locale, origin);
      expect(actions()).toEqual([]);
    });
    test(`${locale} ${origin}: salvar retorna à origem`, async () => {
      await mount(locale);
      await openProfile(locale, origin);
      await edit(locale, "name", "Edited fixture");
      const save = byText(t(locale, "save"));
      expect(save.disabled).toBe(false);
      await click(save);
      destination(locale, origin);
      expect(actions()).toEqual([
        {
          type: "save_profile",
          profile: { ...vpn.profile, name: "Edited fixture" },
        },
      ]);
    });
    test(`${locale} ${origin}: remover com alterações não pede descarte depois`, async () => {
      await mount(locale);
      await openProfile(locale, origin);
      await edit(locale, "name", "Edited fixture");
      await click(byText(t(locale, "removeVpn")));
      const confirmation = [...document.querySelectorAll("dialog")].find(
        (item) =>
          item.getAttribute("aria-label") ===
          t(locale, "removeTitle", { name: vpn.profile.name }),
      );
      expect(confirmation).toBeDefined();
      if (!confirmation) throw new Error("Remove dialog missing");
      await click(byText(t(locale, "remove"), confirmation));
      destination(locale, origin);
      expect(actions()).toEqual([
        { type: "remove_profile", id: vpn.profile.id },
      ]);
    });
  }
  test(`${locale}: Add VPN em Preferências preserva origem pela escolha de tipo`, async () => {
    await mount(locale);
    await click(byLabel(t(locale, "preferences")));
    await click(byText(t(locale, "addVpn")));
    expect(heading()).toBe(t(locale, "newVpn"));
    await click(byText(t(locale, "ipsec") + t(locale, "ipsecHint")));
    expect(document.querySelector("form.profile-form")).not.toBeNull();
    await click(byLabel(t(locale, "back")));
    destination(locale, "preferences");
    expect(actions()).toEqual([]);
  });
  test(`${locale}: Add VPN salva e retorna às Preferências`, async () => {
    await mount(locale);
    await click(byLabel(t(locale, "preferences")));
    await click(byText(t(locale, "addVpn")));
    await click(byText(t(locale, "ipsec") + t(locale, "ipsecHint")));
    await edit(locale, "name", "New fixture");
    await edit(locale, "gateway", "vpn.example.test");
    await edit(locale, "probeHost", "192.0.2.5");
    await click(byText(t(locale, "save")));
    destination(locale, "preferences");
    const sent = actions();
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      type: "save_profile",
      profile: {
        name: "New fixture",
        kind: "ipsec",
        gateway: "vpn.example.test",
        probeHost: "192.0.2.5",
      },
    });
  });
  test(`${locale}: rota criada sem origem volta à Home`, async () => {
    await mount(locale, true);
    await click(byText(t(locale, "install")));
    const confirmation = dialog(locale, "componentInstallTitle");
    expect(confirmation).not.toBeNull();
    if (!confirmation) throw new Error("Install dialog missing");
    await click(byText(t(locale, "install"), confirmation));
    expect(heading()).toBe(t(locale, "newVpn"));
    await click(byText(t(locale, "ipsec") + t(locale, "ipsecHint")));
    expect(document.querySelector("form.profile-form")).not.toBeNull();
    await click(byLabel(t(locale, "back")));
    destination(locale, "home");
    expect(actions()).toEqual([{ type: "install_helper" }]);
  });
  test(`${locale}: saída do rodapé respeita guarda`, async () => {
    await mount(locale);
    await openProfile(locale, "home");
    await edit(locale, "name", "Edited fixture");
    const options = byText(t(locale, "options"));
    await act(async () =>
      options.dispatchEvent(
        new PointerEvent("pointerdown", {
          bubbles: true,
          button: 0,
          ctrlKey: false,
        }),
      ),
    );
    const item = [
      ...document.querySelectorAll<HTMLElement>('[role="menuitem"]'),
    ].find((element) => element.textContent?.trim() === t(locale, "about"));
    expect(item).toBeDefined();
    if (!item) throw new Error("About menu item missing");
    await click(item);
    expect(dialog(locale, "discardTitle")).not.toBeNull();
    expect(input(locale, "name").value).toBe("Edited fixture");
    await click(byText(t(locale, "discard")));
    expect(heading()).toBe(t(locale, "about"));
    expect(dialog(locale, "discardTitle")).toBeNull();
    expect(actions()).toEqual([]);
  });
}
