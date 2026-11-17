import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { GlobalRegistrator } from "@happy-dom/global-registrator";
import { act, createElement } from "react";
import type { Root } from "react-dom/client";
import { VpnCard } from "./components/VpnCard";
import { type Locale, type MessageKey, translate } from "./i18n";
import type { Command, Snapshot, VpnView } from "./model";
import { defaultPreferences } from "./settings";

let App: typeof import("./App").App;
let useAppStateHook: typeof import("./useAppState").useAppState;
let appState:
  | ReturnType<typeof import("./useAppState").useAppState>
  | undefined;
function HookHarness() {
  appState = useAppStateHook();
  return createElement("output", null, appState.error ?? "none");
}
let createRoot: typeof import("react-dom/client").createRoot;
let root: Root | undefined;
let container: HTMLDivElement | undefined;
let originalFetch: typeof fetch;
let commands: Command[];
let snapshot: Snapshot;
let pendingInstall: ((success: boolean) => void) | undefined;
const pendingInstalls = new Set<(success: boolean) => void>();
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
  cleanupVerifying: false,
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
  ({ useAppState: useAppStateHook } = await import("./useAppState"));
});
afterEach(async () => {
  try {
    for (const settle of pendingInstalls) settle(false);
    pendingInstalls.clear();
    pendingInstall = undefined;
    if (root) await act(async () => root?.unmount());
  } finally {
    root = undefined;
    appState = undefined;
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

async function mountComponentScenario(
  initial: Snapshot,
  harness = false,
  locale: Locale = "en-US",
  componentError?: string,
) {
  commands = [];
  snapshot = initial;
  localStorage.setItem(
    "vpnt.preferences.v1",
    JSON.stringify({ locale, theme: "light" }),
  );
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as {
      id: string;
      command: Command;
    };
    commands.push(request.command);
    if (request.command.type === "install_helper") {
      if (componentError)
        return new Response(
          JSON.stringify({ id: request.id, error: componentError }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      return await new Promise<Response>((resolve) => {
        const settle = (success: boolean) => {
          pendingInstalls.delete(settle);
          if (pendingInstall === settle) pendingInstall = undefined;
          if (success)
            snapshot = {
              ...snapshot,
              helper: "installed",
              componentOperation: undefined,
            };
          resolve(
            new Response(
              JSON.stringify(
                success
                  ? { id: request.id, snapshot }
                  : { id: request.id, error: "component_unconfirmed" },
              ),
              { status: 200, headers: { "Content-Type": "application/json" } },
            ),
          );
        };
        pendingInstalls.add(settle);
        pendingInstall = settle;
      });
    }
    return new Response(JSON.stringify({ id: request.id, snapshot }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () =>
    root?.render(createElement(harness ? HookHarness : App)),
  );
}

function componentSnapshot(
  helper: Snapshot["helper"],
  vpns: VpnView[] = [vpn],
): Snapshot {
  return {
    version: "0.1.0",
    demo: false,
    helper,
    preferences: defaultPreferences,
    vpns,
  };
}

for (const locale of ["pt-BR", "en-US"] as const) {
  test(`${locale}: tipo SSL permite editar e salvar as redes exibidas`, async () => {
    await mount(locale);
    await openProfile(locale, "home");
    const typeLabel = [
      ...document.querySelectorAll<HTMLLabelElement>("label.field"),
    ].find(
      (label) => label.querySelector("span")?.textContent === t(locale, "type"),
    );
    const type = typeLabel?.querySelector<HTMLSelectElement>("select");
    if (!type) throw new Error("Type selector missing");
    await act(async () => {
      type.value = "ssl";
      type.dispatchEvent(new Event("change", { bubbles: true }));
    });
    const expectedHint =
      locale === "pt-BR"
        ? "Só estas redes passam pelo túnel. Vazio: as rotas que o gateway publica."
        : "Only these networks use the tunnel. Empty: the routes the gateway publishes.";
    expect(document.querySelector("form.profile-form")?.textContent).toContain(
      expectedHint,
    );
    await edit(locale, "networks", "10.0.0.0/8, 192.168.0.0/16");
    await click(byText(t(locale, "save")));
    const saved = actions().find((command) => command.type === "save_profile");
    expect(saved?.type).toBe("save_profile");
    if (saved?.type !== "save_profile")
      throw new Error("Profile was not saved");
    expect(saved.profile.kind).toBe("ssl");
    expect(saved.profile.networks).toEqual(["10.0.0.0/8", "192.168.0.0/16"]);
  });
}

for (const locale of ["pt-BR", "en-US"] as const) {
  test(`${locale}: verificação continua ocupada após run resolver até o snapshot terminar`, async () => {
    let current: VpnView = { ...vpn, state: "cleanup_unconfirmed" };
    const sent: Command[] = [];
    let resolved = false;
    const render = () =>
      root?.render(
        createElement(VpnCard, {
          vpn: current,
          t: (key, values) => translate(locale, key, values),
          run: async (command) => {
            sent.push(command);
            current = { ...current, cleanupVerifying: true };
            render();
            resolved = true;
            return true;
          },
          navigate: () => {},
          secrets: () => {},
        }),
      );
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
    await act(async () => render());
    const button = byText(
      locale === "pt-BR" ? "Conferir de novo" : "Check again",
      container,
    );
    expect(button.disabled).toBe(false);
    await act(async () => button.click());
    expect(resolved).toBe(true);
    expect(sent).toEqual([{ type: "probe", id: vpn.profile.id }]);
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("aria-busy")).toBe("true");
    expect(button.querySelector("svg.spin")).not.toBeNull();
    await act(async () => button.click());
    expect(sent).toHaveLength(1);
    current = { ...current, cleanupVerifying: false };
    await act(async () => render());
    expect(current.state).toBe("cleanup_unconfirmed");
    expect(button.disabled).toBe(false);
    expect(button.getAttribute("aria-busy")).toBeNull();
    expect(button.querySelector("svg.spin")).toBeNull();
  });
}

for (const locale of ["pt-BR", "en-US"] as const) {
  test(`${locale}: limpeza não confirmada permite conferir novamente sem bloquear outro perfil`, async () => {
    const blocked: VpnView = {
      ...vpn,
      state: "cleanup_unconfirmed" as VpnView["state"],
      hasPassword: true,
      hasPsk: true,
    };
    const other: VpnView = {
      ...vpn,
      profile: { ...vpn.profile, id: "other", name: "Other VPN" },
      hasPassword: true,
      hasPsk: true,
    };
    await mountComponentScenario(
      componentSnapshot("installed", [blocked, other]),
      false,
      locale,
    );
    const card = document.querySelector(
      '[data-testid="vpn-card-profile-fixture"]',
    );
    const otherCard = document.querySelector('[data-testid="vpn-card-other"]');
    if (!card || !otherCard) throw new Error("fixture cards missing");
    const title =
      locale === "pt-BR" ? "Limpeza não confirmada" : "Cleanup unconfirmed";
    const hint =
      locale === "pt-BR"
        ? "A sessão anterior deixou recursos que o VPN Tray não conseguiu confirmar como removidos. Os outros perfis continuam disponíveis."
        : "The previous session left resources VPN Tray could not confirm as removed. Other profiles stay available.";
    const label = locale === "pt-BR" ? "Conferir de novo" : "Check again";
    expect(card.textContent).toContain(title);
    expect(card.textContent).toContain(hint);
    expect(card.textContent).not.toContain(
      locale === "pt-BR" ? "Conectar" : "Connect",
    );
    expect(
      card.querySelector<HTMLButtonElement>("button.switch")?.disabled,
    ).toBe(true);
    expect(
      otherCard.querySelector<HTMLButtonElement>("button.switch")?.disabled,
    ).toBe(false);

    let release: ((value: Response) => void) | undefined;
    let requestId = "";
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      const request = JSON.parse(String(init?.body)) as {
        id: string;
        command: Command;
      };
      commands.push(request.command);
      requestId = request.id;
      if (request.command.type !== "probe") {
        return new Response(JSON.stringify({ id: request.id, snapshot }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return await new Promise<Response>((resolve) => {
        release = resolve;
      });
    }) as typeof fetch;
    try {
      const button = byText(label, card);
      act(() => button.click());
      expect(actions()).toEqual([{ type: "probe", id: blocked.profile.id }]);
      expect(button.disabled).toBe(true);
      expect(button.getAttribute("aria-busy")).toBe("true");
      expect(button.querySelector("svg.spin")).not.toBeNull();
      act(() => button.click());
      expect(actions()).toHaveLength(1);
      await act(async () => {
        release?.(
          new Response(JSON.stringify({ id: requestId, snapshot }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      });
      expect(button.disabled).toBe(false);
      expect(button.querySelector("svg.spin")).toBeNull();
      const otherSwitch =
        otherCard.querySelector<HTMLButtonElement>("button.switch");
      if (!otherSwitch) throw new Error("other profile control missing");
      await click(otherSwitch);
      expect(actions()).toEqual([
        { type: "probe", id: blocked.profile.id },
        { type: "connect", id: other.profile.id },
      ]);
    } finally {
      release?.(
        new Response(JSON.stringify({ id: requestId, snapshot }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }
  });
}

test("aviso Update envia uma vez, permanece na tela e libera retry após falha", async () => {
  await mountComponentScenario(componentSnapshot("outdated"));
  const button = byText(t("en-US", "update"));
  await act(async () => {
    button.click();
    button.click();
  });
  expect(actions()).toEqual([{ type: "install_helper" }]);
  expect(heading()).toBe(t("en-US", "vpns"));
  expect(document.querySelector("dialog")).toBeNull();
  expect(button.disabled).toBe(true);
  expect(button.getAttribute("aria-busy")).toBe("true");
  expect(button.querySelector("svg.spin")).not.toBeNull();
  expect(
    [...document.querySelectorAll('[role="status"]')].filter(
      (item) => item.textContent === t("en-US", "componentInstallPending"),
    ),
  ).toHaveLength(1);
  await click(button);
  expect(actions()).toHaveLength(1);
  await act(async () => pendingInstall?.(false));
  expect(document.querySelector('[role="alert"]')?.textContent).toBe(
    t("en-US", "componentUnconfirmed"),
  );
  const retry = byText(t("en-US", "tryAgain"));
  expect(retry.disabled).toBe(false);
  await click(retry);
  expect(actions()).toEqual([
    { type: "install_helper" },
    { type: "install_helper" },
  ]);
  await act(async () => pendingInstall?.(true));
  expect(heading()).toBe(t("en-US", "vpns"));
});

test("conclusão tardia do Update preserva o rascunho do perfil", async () => {
  await mountComponentScenario(componentSnapshot("outdated"));
  await click(byText(t("en-US", "update")));
  expect(actions()).toEqual([{ type: "install_helper" }]);
  await openProfile("en-US", "home");
  await edit("en-US", "name", "Draft must survive the installer");
  // Control: the same unsaved edit is protected on ordinary navigation.
  await click(byLabel(t("en-US", "back")));
  expect(dialog("en-US", "discardTitle")).not.toBeNull();
  await click(byText(t("en-US", "keepEditing")));
  expect(input("en-US", "name").value).toBe("Draft must survive the installer");
  await act(async () => pendingInstall?.(true));
  expect(document.querySelector("form.profile-form")).not.toBeNull();
  expect(input("en-US", "name").value).toBe("Draft must survive the installer");
  expect(dialog("en-US", "discardTitle")).toBeNull();
  expect(actions()).toEqual([{ type: "install_helper" }]);
});

test("aviso Install envia diretamente sem navegar", async () => {
  await mountComponentScenario(componentSnapshot("missing"));
  const button = byText(t("en-US", "install"));
  await click(button);
  expect(actions()).toEqual([{ type: "install_helper" }]);
  expect(heading()).toBe(t("en-US", "vpns"));
  expect(document.querySelector("dialog")).toBeNull();
  expect(button.disabled).toBe(true);
  expect(button.getAttribute("aria-busy")).toBe("true");
  await act(async () => pendingInstall?.(true));
  expect(heading()).toBe(t("en-US", "vpns"));
});

test("Preferências atualiza diretamente sem navegação intermediária", async () => {
  await mountComponentScenario(componentSnapshot("outdated"));
  await click(byLabel(t("en-US", "preferences")));
  const button = byText(t("en-US", "update"));
  await click(button);
  expect(actions()).toEqual([{ type: "install_helper" }]);
  expect(heading()).toBe(t("en-US", "preferences"));
  expect(document.querySelector("dialog")).toBeNull();
  expect(button.disabled).toBe(true);
  expect(button.getAttribute("aria-busy")).toBe("true");
  await act(async () => pendingInstall?.(true));
});

test("instalação em voo bloqueia os outros pontos de entrada", async () => {
  await mountComponentScenario(componentSnapshot("outdated"));
  await click(byText(t("en-US", "update")));
  await click(byLabel(t("en-US", "preferences")));
  const button = byText(t("en-US", "update"));
  expect(button.disabled).toBe(true);
  expect(button.getAttribute("aria-busy")).toBeNull();
  await click(button);
  expect(actions()).toEqual([{ type: "install_helper" }]);
  expect(
    [...document.querySelectorAll('[role="status"]')].filter(
      (item) => item.textContent === t("en-US", "componentInstallPending"),
    ),
  ).toHaveLength(1);
  await act(async () => pendingInstall?.(true));
  expect(heading()).toBe(t("en-US", "preferences"));
});

test("Update em voo conserva rótulo e aviso após snapshot missing", async () => {
  await mountComponentScenario(componentSnapshot("outdated"));
  await click(byText(t("en-US", "update")));
  snapshot = {
    ...snapshot,
    helper: "missing",
    componentOperation: "installing",
  };
  await click(byLabel(t("en-US", "preferences")));
  await click(byLabel(t("en-US", "startAtLogin")));
  await click(byLabel(t("en-US", "back")));
  expect(document.body.textContent).toContain(t("en-US", "helperOutdated"));
  const button = byText(t("en-US", "update"));
  expect(button.disabled).toBe(true);
  expect(button.getAttribute("aria-busy")).toBe("true");
  expect(button.querySelector("svg.spin")).not.toBeNull();
  expect(document.querySelector("dialog")).toBeNull();
  expect(
    [...document.querySelectorAll('[role="status"]')].filter(
      (item) => item.textContent === t("en-US", "componentInstallPending"),
    ),
  ).toHaveLength(1);
  await act(async () => pendingInstall?.(false));
});

for (const source of ["onboarding", "preferences"] as const) {
  test(`${source}: erro libera retry no mesmo ponto`, async () => {
    await mountComponentScenario(
      componentSnapshot("missing", source === "onboarding" ? [] : [vpn]),
    );
    if (source === "preferences")
      await click(byLabel(t("en-US", "preferences")));
    await click(byText(t("en-US", "install")));
    await act(async () => pendingInstall?.(false));
    expect(document.querySelector('[role="alert"]')?.textContent).toBe(
      t("en-US", "componentUnconfirmed"),
    );
    expect(heading()).toBe(
      t("en-US", source === "preferences" ? "preferences" : "vpns"),
    );
    const retry = byText(t("en-US", "tryAgain"));
    expect(retry.disabled).toBe(false);
    await click(retry);
    expect(actions()).toEqual([
      { type: "install_helper" },
      { type: "install_helper" },
    ]);
    await act(async () => pendingInstall?.(false));
  });
}

test("conclusão de onboarding não muda a tela escolhida depois do clique", async () => {
  await mountComponentScenario(componentSnapshot("missing", []));
  await click(byText(t("en-US", "install")));
  expect(actions()).toEqual([{ type: "install_helper" }]);
  await click(byLabel(t("en-US", "back")));
  expect(heading()).toBe(t("en-US", "vpns"));
  await act(async () => pendingInstall?.(true));
  expect(heading()).toBe(t("en-US", "vpns"));
  expect(document.querySelector("dialog")).toBeNull();
});

test("Preferências sem perfis segue para nova VPN após instalar", async () => {
  await mountComponentScenario(componentSnapshot("missing", []));
  await click(byLabel(t("en-US", "back")));
  await click(byLabel(t("en-US", "preferences")));
  await click(byText(t("en-US", "install")));
  expect(actions()).toEqual([{ type: "install_helper" }]);
  await act(async () => pendingInstall?.(true));
  expect(heading()).toBe(t("en-US", "newVpn"));
  expect(document.querySelector("dialog")).toBeNull();
});

test("conclusão iniciada em Preferências preserva rascunho aberto depois", async () => {
  await mountComponentScenario(componentSnapshot("outdated"));
  await click(byLabel(t("en-US", "preferences")));
  await click(byText(t("en-US", "update")));
  await click(byText(vpn.profile.name + t("en-US", "ipsec")));
  expect(heading()).toBe(vpn.profile.name);
  expect(document.querySelector("form.profile-form")).not.toBeNull();
  await edit("en-US", "name", "Preference draft survives");
  await act(async () => pendingInstall?.(true));
  expect(document.querySelector("form.profile-form")).not.toBeNull();
  expect(input("en-US", "name").value).toBe("Preference draft survives");
  expect(dialog("en-US", "discardTitle")).toBeNull();
  expect(actions()).toEqual([{ type: "install_helper" }]);
});

test("falha tardia não muda a tela nem o rascunho", async () => {
  await mountComponentScenario(componentSnapshot("outdated"));
  await click(byText(t("en-US", "update")));
  await openProfile("en-US", "home");
  await edit("en-US", "name", "Draft survives failure");
  await act(async () => pendingInstall?.(false));
  expect(document.querySelector("form.profile-form")).not.toBeNull();
  expect(input("en-US", "name").value).toBe("Draft survives failure");
  expect(dialog("en-US", "discardTitle")).toBeNull();
  expect(document.querySelector('[role="alert"]')?.textContent).toBe(
    t("en-US", "componentUnconfirmed"),
  );
});

test("Onboarding atualiza em um clique sem confirmação", async () => {
  await mountComponentScenario(componentSnapshot("outdated", []));
  const button = byText(t("en-US", "update"));
  await click(button);
  expect(actions()).toEqual([{ type: "install_helper" }]);
  expect(document.querySelector("dialog")).toBeNull();
  expect(button.disabled).toBe(true);
  expect(button.getAttribute("aria-busy")).toBe("true");
  await act(async () => pendingInstall?.(true));
  expect(heading()).toBe(t("en-US", "newVpn"));
});

test("Onboarding instala em um clique sem confirmação", async () => {
  await mountComponentScenario(componentSnapshot("missing", []));
  const button = byText(t("en-US", "install"));
  await click(button);
  expect(actions()).toEqual([{ type: "install_helper" }]);
  expect(document.querySelector("dialog")).toBeNull();
  expect(button.disabled).toBe(true);
  expect(button.getAttribute("aria-busy")).toBe("true");
  expect(button.querySelector("svg.spin")).not.toBeNull();
  expect(
    [...document.querySelectorAll('[role="status"]')].filter(
      (item) => item.textContent === t("en-US", "componentInstallPending"),
    ),
  ).toHaveLength(1);
  await act(async () => pendingInstall?.(true));
  expect(heading()).toBe(t("en-US", "newVpn"));
});

test("Preferências instala em um clique e Remover ainda pede confirmação", async () => {
  await mountComponentScenario(componentSnapshot("missing"));
  await click(byLabel(t("en-US", "preferences")));
  const button = byText(t("en-US", "install"));
  await click(button);
  expect(actions()).toEqual([{ type: "install_helper" }]);
  expect(heading()).toBe(t("en-US", "preferences"));
  expect(document.querySelector("dialog")).toBeNull();
  expect(button.disabled).toBe(true);
  expect(button.getAttribute("aria-busy")).toBe("true");
  expect(button.querySelector("svg.spin")).not.toBeNull();
  expect(
    [...document.querySelectorAll('[role="status"]')].filter(
      (item) => item.textContent === t("en-US", "componentInstallPending"),
    ),
  ).toHaveLength(1);
  await act(async () => pendingInstall?.(true));
  expect(heading()).toBe(t("en-US", "vpns"));
  await click(byLabel(t("en-US", "preferences")));
  await click(byLabel(t("en-US", "remove")));
  expect(dialog("en-US", "componentRemoveTitle")).not.toBeNull();
  expect(actions()).toEqual([{ type: "install_helper" }]);
});

for (const [state, cleaning] of [
  ["connecting", false],
  ["verifying", false],
  ["connected", false],
  ["unresponsive", false],
  ["reconnecting", false],
  ["disconnecting", false],
  ["gateway_timeout", true],
] as const) {
  test(`Update recusa ${state} cleaning=${cleaning}`, async () => {
    await mountComponentScenario(
      componentSnapshot("outdated", [{ ...vpn, state, cleaning }]),
    );
    const button = byText(t("en-US", "update"));
    expect(button.disabled).toBe(true);
    expect(document.body.textContent).toContain(
      t("en-US", "componentUpdateBlocked"),
    );
    await click(button);
    expect(actions()).toEqual([]);
  });
}

test("ação compartilhada recusa conexão ativa mesmo sem depender do botão", async () => {
  await mountComponentScenario(
    componentSnapshot("outdated", [{ ...vpn, state: "connected" }]),
    true,
  );
  if (!appState) throw new Error("hook not mounted");
  await act(async () => {
    void appState?.installComponent("panel");
  });
  expect(actions()).toEqual([]);
  expect(appState.installAttempt).toBeUndefined();
});

test("VPN ativa em outro perfil também bloqueia Update", async () => {
  const other: VpnView = {
    ...vpn,
    profile: { ...vpn.profile, id: "other", name: "Other" },
    state: "connected",
  };
  await mountComponentScenario(componentSnapshot("outdated", [vpn, other]));
  const button = byText(t("en-US", "update"));
  expect(button.disabled).toBe(true);
  expect(document.body.textContent).toContain(
    t("en-US", "componentUpdateBlocked"),
  );
  await click(button);
  expect(actions()).toEqual([]);
});

test("operação do backend mantém Update desabilitado sem outro pedido", async () => {
  await mountComponentScenario({
    ...componentSnapshot("outdated"),
    componentOperation: "installing",
  });
  const button = byText(t("en-US", "update"));
  expect(button.disabled).toBe(true);
  await click(button);
  expect(actions()).toEqual([]);
});

test("Preferências exibe dica e impede instalação com VPN ativa", async () => {
  await mountComponentScenario(
    componentSnapshot("missing", [{ ...vpn, state: "connected" }]),
  );
  await click(byLabel(t("en-US", "preferences")));
  const button = byText(t("en-US", "install"));
  expect(button.disabled).toBe(true);
  expect(document.body.textContent).toContain(
    t("en-US", "componentInstallBlocked"),
  );
  await click(button);
  expect(actions()).toEqual([]);
});

test("bridge dá dez minutos só ao componente em HTTP e IPC", async () => {
  // Use a fresh module bound to this test's window, not a bridge module that
  // another test may have imported while its own window stub was installed.
  const originalReply = window.__vpntReply;
  const modulePath = "./bridge.ts?component-timeout-fixture";
  const { invoke } = (await import(modulePath)) as typeof import("./bridge");
  const data: Snapshot = {
    version: "0.1.0",
    demo: false,
    helper: "installed",
    preferences: defaultPreferences,
    vpns: [vpn],
  };
  const originalTimeout = AbortSignal.timeout;
  const originalTimer = globalThis.setTimeout;
  const originalIpc = window.ipc;
  const durations: number[] = [];
  try {
    AbortSignal.timeout = (milliseconds) => {
      durations.push(milliseconds);
      return new AbortController().signal;
    };
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      const request = JSON.parse(String(init?.body)) as { id: string };
      return new Response(JSON.stringify({ id: request.id, snapshot: data }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;
    const cases: Array<[Command, number]> = [
      [{ type: "install_helper" }, 610000],
      [{ type: "remove_helper" }, 610000],
      [{ type: "toggle", id: "one" }, 120000],
      [{ type: "connect", id: "one" }, 120000],
      [{ type: "disconnect", id: "one" }, 120000],
      [{ type: "reconnect", id: "one" }, 120000],
      [
        { type: "save_secrets", id: "one", password: "fictional", psk: "" },
        120000,
      ],
      [{ type: "save_profile", profile: vpn.profile }, 120000],
      [{ type: "remove_profile", id: "one" }, 120000],
      [{ type: "get_snapshot" }, 10000],
      [{ type: "probe", id: "one" }, 10000],
      [{ type: "disconnect_all" }, 10000],
      [{ type: "hide" }, 10000],
      [{ type: "open_project" }, 10000],
      [{ type: "quit" }, 10000],
      [{ type: "resize", height: 320 }, 10000],
      [{ type: "set_demo_state", id: "one", state: "off" }, 10000],
      [{ type: "set_preferences", preferences: defaultPreferences }, 10000],
    ];
    for (const [command] of cases) await invoke(command);
    expect(durations).toEqual(cases.map(([, timeout]) => timeout));
    const timers: number[] = [];
    globalThis.setTimeout = ((
      handler: TimerHandler,
      timeout?: number,
      ...args: unknown[]
    ) => {
      timers.push(timeout ?? 0);
      return originalTimer(handler, timeout, ...args);
    }) as typeof setTimeout;
    window.ipc = {
      postMessage(body) {
        const request = JSON.parse(body) as { id: string };
        queueMicrotask(() =>
          window.__vpntReply?.({ id: request.id, snapshot: data }),
        );
      },
    };
    await invoke({ type: "install_helper" });
    await invoke({ type: "remove_helper" });
    await invoke({ type: "get_snapshot" });
    expect(timers).toEqual([610000, 610000, 10000]);
  } finally {
    AbortSignal.timeout = originalTimeout;
    globalThis.setTimeout = originalTimer;
    if (originalIpc) window.ipc = originalIpc;
    else delete window.ipc;
    if (originalReply) window.__vpntReply = originalReply;
    else delete window.__vpntReply;
  }
});

test("erro de componente some quando polling confirma instalação, sem nova instalação", async () => {
  let nextPoll: (() => void) | undefined;
  commands = [];
  snapshot = {
    version: "0.1.0",
    demo: false,
    helper: "outdated",
    preferences: defaultPreferences,
    vpns: [vpn],
  };
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as {
      id: string;
      command: Command;
    };
    commands.push(request.command);
    const observed = snapshot;
    if (request.command.type === "get_snapshot") {
      const done = nextPoll;
      nextPoll = undefined;
      done?.();
    }
    return new Response(
      JSON.stringify({ id: request.id, snapshot: observed }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as typeof fetch;
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root?.render(createElement(HookHarness)));
  async function poll(next: Snapshot) {
    await act(async () => {
      const received = new Promise<void>((resolve) => {
        nextPoll = resolve;
      });
      snapshot = next;
      await received;
    });
  }
  for (const error of ["componentExpired", "componentUnconfirmed"] as const) {
    await poll({ ...snapshot, helper: "outdated" });
    if (!appState) throw new Error("hook not mounted");
    await act(async () => appState?.setError(error));
    expect(document.querySelector("output")?.textContent).toBe(error);
    await poll({ ...snapshot, helper: "installed" });
    expect(document.querySelector("output")?.textContent).toBe("none");
  }
  expect(
    commands.filter(
      (command) =>
        command.type === "install_helper" || command.type === "remove_helper",
    ),
  ).toHaveLength(0);
});

test("Log segmentado troca a aba e mantém navegação por teclado", async () => {
  const { Log } = await import("./screens/Log");
  const second: VpnView = {
    ...vpn,
    profile: { ...vpn.profile, id: "other", name: "Other VPN" },
  };
  const data: Snapshot = {
    version: "0.1.0",
    demo: false,
    helper: "installed",
    preferences: defaultPreferences,
    vpns: [vpn, second],
  };
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () =>
    root?.render(
      createElement(Log, {
        snapshot: data,
        navigate: () => {},
        run: async () => true,
        t: (key, values) => translate("en-US", key, values),
        locale: "en-US",
      }),
    ),
  );
  const tabs = [
    ...document.querySelectorAll<HTMLButtonElement>('[role="tab"]'),
  ];
  expect(tabs).toHaveLength(2);
  expect(tabs[0]?.getAttribute("aria-selected")).toBe("true");
  expect(tabs[1]?.getAttribute("aria-selected")).toBe("false");
  expect(tabs[0]?.classList.contains("primary")).toBe(false);
  if (!tabs[0] || !tabs[1]) throw new Error("missing log tabs");
  await click(tabs[1]);
  expect(tabs[1].getAttribute("aria-selected")).toBe("true");
  expect(
    document
      .querySelector('[role="tabpanel"]')
      ?.getAttribute("aria-labelledby"),
  ).toBe(tabs[1].id);
  await act(async () =>
    tabs[1]?.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }),
    ),
  );
  expect(tabs[0].getAttribute("aria-selected")).toBe("true");
  expect(document.activeElement).toBe(tabs[0]);
  await act(async () =>
    tabs[0]?.dispatchEvent(
      new KeyboardEvent("keydown", { key: "End", bubbles: true }),
    ),
  );
  expect(tabs[1].getAttribute("aria-selected")).toBe("true");
  expect(document.activeElement).toBe(tabs[1]);
});

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
    expect(document.querySelector("dialog")).toBeNull();
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

for (const locale of ["en-US", "pt-BR"] as const) {
  test(`${locale}: sessão anterior no primeiro snapshot avisa sem instalar`, async () => {
    await mountComponentScenario(
      componentSnapshot("previous_session_finishing", []),
      false,
      locale,
    );
    expect(heading()).toBe(t(locale, "vpns"));
    const notice = [...document.querySelectorAll('[role="status"]')].find(
      (element) =>
        element.textContent?.trim() === t(locale, "helperPreviousSession"),
    );
    expect(notice?.querySelector("svg.spin")).not.toBeNull();
    const buttons = [...document.querySelectorAll<HTMLButtonElement>("button")];
    expect(
      buttons.some((button) =>
        [t(locale, "install"), t(locale, "update")].includes(
          button.textContent?.trim() ?? "",
        ),
      ),
    ).toBe(false);
    expect(actions()).toEqual([]);
    await click(byLabel(t(locale, "preferences")));
    expect(heading()).toBe(t(locale, "preferences"));
    expect(document.body.textContent).toContain(
      t(locale, "helperPreviousSession"),
    );
    const controls = [
      ...document.querySelectorAll<HTMLButtonElement>("button"),
    ];
    expect(
      controls.some((button) =>
        [t(locale, "install"), t(locale, "update")].includes(
          button.textContent?.trim() ?? "",
        ),
      ),
    ).toBe(false);
    expect(
      document.querySelector(`button[aria-label="${t(locale, "remove")}"]`),
    ).toBeNull();
    expect(actions()).toEqual([]);
  });

  test(`${locale}: erro de sessão anterior tem mensagem própria`, async () => {
    await mountComponentScenario(
      componentSnapshot("missing"),
      false,
      locale,
      "previous_session_finishing",
    );
    await click(byText(t(locale, "install")));
    expect(document.querySelector('[role="alert"]')?.textContent).toBe(
      t(locale, "previousSessionFinishing"),
    );
    expect(actions()).toEqual([{ type: "install_helper" }]);
  });
}

test("sessão anterior fecha confirmação de remoção aberta sem enviar remoção", async () => {
  await mountComponentScenario(componentSnapshot("installed"));
  await click(byLabel(t("en-US", "preferences")));
  await click(byLabel(t("en-US", "remove")));
  expect(dialog("en-US", "componentRemoveTitle")).not.toBeNull();
  snapshot = { ...snapshot, helper: "previous_session_finishing" };
  await click(byLabel(t("en-US", "startAtLogin")));
  expect(dialog("en-US", "componentRemoveTitle")).toBeNull();
  expect(actions().some((command) => command.type === "remove_helper")).toBe(
    false,
  );
});

test("sessão anterior reconcilia onboarding durante instalação pendente", async () => {
  await mountComponentScenario(componentSnapshot("missing", []), true);
  expect(appState?.route).toEqual({ page: "onboarding" });
  await act(async () => {
    void appState?.installComponent("onboarding");
  });
  expect(actions()).toEqual([{ type: "install_helper" }]);
  snapshot = { ...snapshot, helper: "previous_session_finishing" };
  await act(async () => {
    await appState?.run({ type: "get_snapshot" });
  });
  expect(appState?.route).toEqual({ page: "panel" });
  expect(actions()).toEqual([{ type: "install_helper" }]);
  await act(async () => pendingInstall?.(false));
});
