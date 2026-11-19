import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { GlobalRegistrator } from "@happy-dom/global-registrator";
import { act, createElement } from "react";
import type { Root } from "react-dom/client";
import type { Command, Reply, Snapshot, VpnView } from "./model";
import { blankProfile } from "./profileDefaults";
import { defaultPreferences } from "./settings";

const marker = "FAKE-OVPN-NOT-FOR-THE-DOM";
const content = `remote vpn.example.test 443 udp\n<ca>\n${marker}\n</ca>\n`;
const certificate = {
  id: "00af",
  subject: "Test holder",
  issuer: "Test issuer",
  notBefore: "2026-01-01T00:00:00Z",
  notAfter: "2027-01-01T00:00:00Z",
};
const existing: VpnView = {
  profile: {
    ...blankProfile("ovpn"),
    name: "Example OVPN",
    gateway: "vpn.example.test",
    probeHost: "192.0.2.1",
    ovpn: {
      certificateId: certificate.id,
      module: "/usr/lib/libserproidp11.so",
      tls: "pkcs1_only",
    },
  },
  state: "off",
  cleaning: false,
  cleanupVerifying: false,
  hasPassword: false,
  hasPsk: false,
  log: [],
};
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
// Imported after the DOM is registered: the module graph is shared by every
// test file in the process, so a static import here would evaluate the app
// (and the libraries it pulls in) before any document exists.
let App: typeof import("./App").App;
let root: Root | undefined;
let container: HTMLDivElement | undefined;
let commands: Command[];
let replyFor: (command: Command) => Omit<Reply, "id"> | undefined;
const originalFetch = globalThis.fetch;

beforeAll(async () => {
  GlobalRegistrator.register({ url: "http://localhost/" });
  scope.IS_REACT_ACT_ENVIRONMENT = true;
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
    delete document.documentElement.dataset.platform;
    localStorage.clear();
    globalThis.fetch = originalFetch;
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

async function mount(vpns: VpnView[] = [], locale = "en-US") {
  commands = [];
  replyFor = (command) => {
    if (command.type === "inspect_ovpn")
      return {
        ovpn: { name: "Imported VPN", gateway: "vpn.example.test", port: 8443 },
      };
    if (command.type === "list_certificates")
      return { certificates: [certificate] };
  };
  let snapshot: Snapshot = {
    version: "0.1.0",
    demo: false,
    helper: "installed",
    preferences: defaultPreferences,
    vpns,
  };
  localStorage.setItem(
    "vpnt.preferences.v1",
    JSON.stringify({ locale, theme: "light" }),
  );
  globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
    const { id, command } = JSON.parse(String(init?.body)) as {
      id: string;
      command: Command;
    };
    commands.push(command);
    if (command.type === "save_profile") {
      snapshot = {
        ...snapshot,
        vpns: [{ ...existing, profile: command.profile }],
      };
    }
    return Response.json({ id, ...(replyFor(command) ?? { snapshot }) });
  }) as typeof fetch;
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root?.render(createElement(App)));
}

function button(text: string): HTMLButtonElement {
  const found = [...document.querySelectorAll("button")].find(
    (el) =>
      el.textContent?.trim() === text || el.getAttribute("aria-label") === text,
  );
  if (!found) throw new Error(`No button: ${text}`);
  return found;
}

async function click(element: HTMLElement) {
  await act(async () => element.click());
}

function field(label: string): HTMLInputElement {
  const found = [...document.querySelectorAll("label.field")]
    .find((el) => el.querySelector("span")?.textContent === label)
    ?.querySelector("input");
  if (!found) throw new Error(`No input: ${label}`);
  return found;
}

async function edit(label: string, value: string) {
  const input = field(label);
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set;
  if (!setter) throw new Error("Missing input setter");
  await act(async () => {
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function chooseFile(value: string | ArrayBuffer) {
  const input = document.querySelector<HTMLInputElement>('input[type="file"]');
  if (!input) throw new Error("Missing file input");
  const file = new File([value], "synthetic.ovpn");
  const files = new DataTransfer();
  files.items.add(file);
  await act(async () => {
    input.files = files.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
}

async function createProfile() {
  document.documentElement.dataset.platform = "linux";
  await mount();
  await click(button("Add VPN"));
  const option = [...document.querySelectorAll("button")].find((el) =>
    el.textContent?.startsWith("OpenVPN"),
  );
  if (!option) throw new Error("Missing OpenVPN option");
  await click(option);
}

test("OVPN import fills metadata, keeps the text out of the DOM and sends it when saving", async () => {
  await createProfile();
  expect(button("Save").disabled).toBe(true);
  await chooseFile(content);
  expect(field("Name").value).toBe("Imported VPN");
  expect(document.body.textContent).toContain("vpn.example.test");
  expect(document.body.textContent).toContain("8443");
  expect(document.body.innerHTML).not.toContain(marker);
  await edit("Address", "192.0.2.1");
  await edit("Internal domains", "Serpro");
  await click(button("List certificates"));
  expect(
    commands.find((command) => command.type === "list_certificates"),
  ).toEqual({
    type: "list_certificates",
    module: "/usr/lib/libserproidp11.so",
  });
  expect(document.body.textContent).toContain("Test holder");
  expect(document.body.textContent).toContain("Test issuer");
  expect(document.body.textContent).toContain("2026-01-01");
  expect(document.body.textContent).toContain("2027-01-01");
  const choice = document.querySelector<HTMLInputElement>(
    'input[type="radio"]',
  );
  if (!choice) throw new Error("Missing certificate choice");
  await click(choice);
  expect(button("Save").disabled).toBe(false);
  await click(button("Save"));
  const save = commands.find((command) => command.type === "save_profile");
  expect(save).toMatchObject({
    type: "save_profile",
    profile: {
      kind: "ovpn",
      name: "Imported VPN",
      gateway: "vpn.example.test",
      port: 8443,
      ovpn: {
        certificateId: "00af",
        module: "/usr/lib/libserproidp11.so",
        tls: "pkcs1_only",
      },
      dnsDomains: ["serpro"],
      username: "",
      networks: [],
      certificate: "",
    },
    ovpn_config: content,
  });
  expect(document.body.innerHTML).not.toContain(marker);
});

async function selectKind(kind: string) {
  const select = [...document.querySelectorAll("label.field")]
    .find((el) => el.querySelector("span")?.textContent === "Type")
    ?.querySelector("select");
  if (!select) throw new Error("Missing type select");
  const setter = Object.getOwnPropertyDescriptor(
    HTMLSelectElement.prototype,
    "value",
  )?.set;
  if (!setter) throw new Error("Missing select setter");
  await act(async () => {
    setter.call(select, kind);
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });
}

test("A username typed under SSL does not block saving after switching to OVPN", async () => {
  await createProfile();
  await selectKind("ssl");
  await edit("Username", "$(copied)");
  await selectKind("ovpn");
  await chooseFile(content);
  await edit("Address", "192.0.2.1");
  await click(button("List certificates"));
  const choice = document.querySelector<HTMLInputElement>(
    'input[type="radio"]',
  );
  if (!choice) throw new Error("Missing certificate choice");
  await click(choice);
  expect(button("Save").disabled).toBe(false);
});

test("OVPN import localizes a refusal and rejects oversized file and JSON before transport", async () => {
  await createProfile();
  replyFor = () => ({ error: "invalid_ovpn", detail: "up" });
  await chooseFile(content);
  expect(document.querySelector('[role="alert"]')?.textContent).toContain(
    "forbidden directive: up",
  );
  const count = () =>
    commands.filter((command) => command.type === "inspect_ovpn").length;
  expect(count()).toBe(1);
  for (const oversized of ["a".repeat(65537), '"'.repeat(40000)]) {
    await chooseFile(oversized);
    expect(document.querySelector('[role="alert"]')?.textContent).toContain(
      "64 KiB",
    );
    expect(count()).toBe(1);
  }
  await chooseFile(new Uint8Array([0xff]).buffer);
  expect(document.querySelector('[role="alert"]')?.textContent).toContain(
    "UTF-8",
  );
  expect(count()).toBe(1);
});

test("OVPN certificate listing reports empty and error states and allows retry", async () => {
  await createProfile();
  replyFor = () => ({ certificates: [] });
  await click(button("List certificates"));
  expect(document.body.textContent).toContain(
    "No certificates with a private key found.",
  );
  replyFor = () => ({ error: "token_unavailable" });
  await click(button("Try again"));
  expect(document.querySelector('[role="alert"]')?.textContent).toContain(
    "Could not list certificates from the token.",
  );
  replyFor = () => ({ certificates: [certificate] });
  await click(button("Try again"));
  expect(document.body.textContent).toContain("Test holder");
  expect(document.querySelector('[role="alert"]')).toBeNull();
});

test("untrusted module displays a distinct localized error", async () => {
  await createProfile();
  replyFor = () => ({ error: "untrusted_module" });
  await click(button("List certificates"));
  expect(document.querySelector('[role="alert"]')?.textContent).toContain(
    "The PKCS#11 module or its folders are not trusted.",
  );
  const { catalogs } = await import("./i18n");
  expect(catalogs["pt-BR"].ovpnUntrustedModule).toBe(
    "O módulo PKCS#11 ou suas pastas não são confiáveis.",
  );
});

test("Editing OVPN without importing omits the config and never prompts for secrets", async () => {
  await mount([existing]);
  await click(button("Example OVPN: Disconnected"));
  expect(commands).toContainEqual({ type: "connect", id: existing.profile.id });
  expect(document.querySelector("dialog")).toBeNull();
  expect(document.body.textContent).not.toContain("Password required");
  await click(button("Details for Example OVPN"));
  expect(document.body.textContent).not.toContain("Secrets");
  await click(button("Save"));
  const save = commands.find((command) => command.type === "save_profile");
  expect(save).toBeDefined();
  expect(save).not.toHaveProperty("ovpn_config");
});

for (const [locale, status, detail, cancel] of [
  [
    "en-US",
    "Waiting for approval",
    "Approve the request in your certificate app",
    "Cancel",
  ],
  [
    "pt-BR",
    "Aguardando aprovação",
    "Aprove o acesso no app do seu certificado",
    "Cancelar",
  ],
]) {
  test(`OVPN approval is visible and cancelable in ${locale}`, async () => {
    await mount([{ ...existing, state: "awaiting_approval" }], locale);
    expect(document.body.textContent).toContain(status);
    expect(document.body.textContent).toContain(detail);
    expect(button(`Example OVPN: ${status}`).disabled).toBe(true);
    const cancelButton = button(cancel);
    expect(cancelButton.querySelector("svg")).not.toBeNull();
    await click(cancelButton);
    expect(commands).toContainEqual({
      type: "disconnect",
      id: existing.profile.id,
    });
    expect(document.querySelector("dialog")).toBeNull();
  });
}

test("macOS starts with an empty module and accepts both library suffixes", async () => {
  await mount();
  await click(button("Add VPN"));
  const option = [...document.querySelectorAll("button")].find((el) =>
    el.textContent?.startsWith("OpenVPN"),
  );
  if (!option) throw new Error("Missing OpenVPN option");
  await click(option);
  expect(field("PKCS#11 module").value).toBe("");
  for (const path of ["/fixture/token.so", "/fixture/token.dylib"]) {
    await edit("PKCS#11 module", path);
    await click(button("List certificates"));
    expect(commands.at(-1)).toEqual({
      type: "list_certificates",
      module: path,
    });
  }
  for (const path of [
    "relative.so",
    "/fixture/../token.dylib",
    "/fixture/token",
  ]) {
    await edit("PKCS#11 module", path);
    expect(button("List certificates").disabled).toBe(true);
  }
});

for (const [locale, expected] of [
  [
    "en-US",
    "The VPN client is unavailable or this profile type is not supported on this platform.",
  ],
  [
    "pt-BR",
    "O cliente de VPN está indisponível ou este tipo de perfil não é compatível com esta plataforma.",
  ],
] as const) {
  test(`${locale}: unsupported OVPN is shown without claiming a tunnel`, async () => {
    await mount([{ ...existing, state: "missing_program" }], locale);
    expect(document.body.textContent).toContain(expected);
    expect(commands.some((command) => command.type === "connect")).toBe(false);
  });
}
