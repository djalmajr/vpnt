import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { GlobalRegistrator } from "@happy-dom/global-registrator";
import { act, createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { T } from "./components/common";
import { RemoveDialogBody } from "./components/RemoveDialog";
import { translate } from "./i18n";
import type { VpnView } from "./model";
import { isLinuxPlatform } from "./platform";
import { blankProfile } from "./profileDefaults";
import { Profile } from "./screens/Profile";

const scope = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};
const globals = new Map(
  Reflect.ownKeys(globalThis).map((key) => [
    key,
    Reflect.getOwnPropertyDescriptor(globalThis, key),
  ]),
);
let createRoot: typeof import("react-dom/client").createRoot;
let root: ReturnType<typeof createRoot> | undefined;
let container: HTMLDivElement | undefined;

beforeAll(async () => {
  GlobalRegistrator.register({ url: "http://localhost/" });
  scope.IS_REACT_ACT_ENVIRONMENT = true;
  ({ createRoot } = await import("react-dom/client"));
});

afterEach(async () => {
  try {
    if (root) await act(async () => root?.unmount());
  } finally {
    root = undefined;
    container?.remove();
    container = undefined;
    delete document.documentElement.dataset.platform;
  }
});

afterAll(async () => {
  try {
    await GlobalRegistrator.unregister();
  } finally {
    for (const key of Reflect.ownKeys(globalThis)) {
      if (!globals.has(key)) Reflect.deleteProperty(globalThis, key);
    }
    for (const [key, descriptor] of globals) {
      if (descriptor) Reflect.defineProperty(globalThis, key, descriptor);
    }
  }
});

const vpn: VpnView = {
  profile: {
    ...blankProfile("ipsec"),
    name: "FixtureVPN",
    gateway: "vpn.example.test",
    probeHost: "192.0.2.1",
  },
  state: "off",
  cleaning: false,
  cleanupVerifying: false,
  hasPassword: false,
  hasPsk: false,
  log: [],
};

function platform(linux: boolean): boolean {
  if (linux) document.documentElement.dataset.platform = "linux";
  else delete document.documentElement.dataset.platform;
  return isLinuxPlatform();
}

async function mountProfile(locale: "en-US" | "pt-BR") {
  let finish!: (ok: boolean) => void;
  let saved = 0;
  const pending = new Promise<boolean>((resolve) => {
    finish = resolve;
  });
  const host = document.createElement("div");
  document.body.append(host);
  container = host;
  root = createRoot(host);
  const t: T = (key, values) => translate(locale, key, values);
  await act(async () => {
    root?.render(
      createElement(Profile, {
        vpn,
        t,
        navigate: () => {},
        registerNavigationGuard: () => {},
        saved: () => {
          saved += 1;
        },
        run: async () => pending,
        secrets: () => {},
        remove: () => {},
      }),
    );
  });
  return {
    host,
    t,
    finish,
    pending,
    savedCount: () => saved,
  };
}

for (const locale of ["en-US", "pt-BR"] as const) {
  test(`${locale}: perfil no Linux cala a dica de administrador e mostra savePending ao salvar`, async () => {
    expect(platform(true)).toBe(true);
    const { host, t, finish, pending } = await mountProfile(locale);
    const form = host.querySelector("form");
    expect(form).not.toBeNull();
    expect(host.textContent).not.toContain(t("saveRequiresAdmin"));
    expect(host.textContent).not.toContain(t("savePending"));
    expect(host.textContent).not.toContain(t("adminPending"));

    await act(async () => {
      form?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
    });
    expect(form?.getAttribute("aria-busy")).toBe("true");
    expect(host.textContent).toContain(t("savePending"));
    expect(host.textContent).not.toContain(t("saveRequiresAdmin"));
    expect(host.textContent).not.toContain(t("adminPending"));

    await act(async () => {
      finish(true);
      await pending;
    });
    expect(form?.getAttribute("aria-busy")).not.toBe("true");
    expect(host.textContent).not.toContain(t("savePending"));
    expect(host.textContent).not.toContain(t("saveRequiresAdmin"));
  });

  test(`${locale}: perfil sem o marcador mantém saveRequiresAdmin e adminPending`, async () => {
    expect(platform(false)).toBe(false);
    const { host, t, finish, pending } = await mountProfile(locale);
    const form = host.querySelector("form");
    expect(host.textContent).toContain(t("saveRequiresAdmin"));
    expect(host.textContent).not.toContain(t("savePending"));

    await act(async () => {
      form?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
    });
    expect(host.textContent).toContain(t("adminPending"));
    expect(host.textContent).not.toContain(t("savePending"));
    expect(host.textContent).not.toContain(t("saveRequiresAdmin"));

    await act(async () => {
      finish(true);
      await pending;
    });
    expect(host.textContent).toContain(t("saveRequiresAdmin"));
  });

  test(`${locale}: diálogo de remoção usa removePending no Linux e adminPending sem o marcador`, async () => {
    const t: T = (key, values) => translate(locale, key, values);
    const render = (saving: boolean) =>
      renderToStaticMarkup(
        createElement(RemoveDialogBody, {
          saving,
          confirm: () => {},
          close: () => {},
          t,
        }),
      );
    expect(platform(true)).toBe(true);
    expect(render(false)).toContain(t("removeHint"));
    expect(render(false)).not.toContain(t("removePending"));
    expect(render(true)).toContain(t("removePending"));
    expect(render(true)).not.toContain(t("adminPending"));

    expect(platform(false)).toBe(false);
    expect(render(false)).toContain(t("removeHint"));
    expect(render(true)).toContain(t("adminPending"));
    expect(render(true)).not.toContain(t("removePending"));
  });
}

test("erro de salvamento no Linux volta à dica ociosa, sem texto de administrador", async () => {
  expect(platform(true)).toBe(true);
  const t: T = (key, values) => translate("en-US", key, values);
  const { host, finish, pending, savedCount } = await mountProfile("en-US");
  const form = host.querySelector("form");
  await act(async () => {
    form?.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
  });
  expect(host.textContent).toContain(t("savePending"));

  await act(async () => {
    finish(false);
    await pending;
  });
  // run() resolves false: no navigation and no admin hint; the existing App
  // error notice remains the only place that reports the failed command.
  expect(savedCount()).toBe(0);
  expect(form?.getAttribute("aria-busy")).not.toBe("true");
  expect(host.textContent).not.toContain(t("savePending"));
  expect(host.textContent).not.toContain(t("saveRequiresAdmin"));
  expect(host.textContent).not.toContain(t("adminPending"));
});

test("as chaves novas também existem em português", () => {
  expect(translate("en-US", "savePending")).toBe("Saving…");
  expect(translate("pt-BR", "savePending")).toBe("Salvando…");
  expect(translate("en-US", "removePending")).toBe("Removing…");
  expect(translate("pt-BR", "removePending")).toBe("Removendo…");
});
