import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { isValidElement, type ReactElement, type ReactNode } from "react";
import type { T } from "./components/common";
import { VpnCard } from "./components/VpnCard";
import { translate } from "./i18n";
import {
  active,
  type Command,
  type ConnectionState,
  states,
  type VpnView,
} from "./model";
import type { Run } from "./navigation";

/** The root brief authorizes exactly this fixture; it is not a real profile and
 * holds no real secret. */
const profile: VpnView["profile"] = {
  id: "intent-fixture",
  name: "FixtureVPN",
  kind: "ipsec",
  gateway: "vpn.example.test",
  username: "fixture",
  networks: ["192.0.2.0/24"],
  port: 500,
  certificate: "",
  probeHost: "192.0.2.1",
  probePort: 8443,
  probeMethod: "ping_tcp",
};

const t: T = (key, values) => translate("pt-BR", key, values);

const view = (state: ConnectionState): VpnView => ({
  profile,
  state,
  hasPassword: true,
  hasPsk: true,
  log: [],
});

type Props = Record<string, unknown> & { children?: ReactNode };

const props = (element: ReactElement): Props => element.props as Props;

/** Typed traversal of the returned elements: VpnCard is a pure function
 * component, so its handlers are executable without a DOM renderer. */
function walk(node: ReactNode, visit: (element: ReactElement) => void) {
  if (Array.isArray(node)) {
    for (const child of node) walk(child, visit);
    return;
  }
  if (typeof node !== "object" || node === null || !isValidElement(node))
    return;
  visit(node);
  walk(props(node).children, visit);
}

function textOf(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textOf).join("");
  if (typeof node === "object" && node !== null && isValidElement(node))
    return textOf(props(node).children);
  return "";
}

function buttons(tree: ReactNode): ReactElement[] {
  const found: ReactElement[] = [];
  walk(tree, (element) => {
    if (element.type === "button") found.push(element);
  });
  return found;
}

function principal(tree: ReactNode): ReactElement {
  const matches: ReactElement[] = [];
  walk(tree, (element) => {
    if (props(element).className === "card-toggle") matches.push(element);
  });
  expect(matches).toHaveLength(1);
  return matches[0];
}

function click(element: ReactElement) {
  const handler = props(element).onClick;
  if (typeof handler === "function") (handler as () => void)();
}

function card(state: ConnectionState) {
  const commands: Command[] = [];
  let secretRequests = 0;
  const run: Run = async (command) => {
    commands.push(command);
    return true;
  };
  const tree = VpnCard({
    vpn: view(state),
    t,
    run,
    navigate: () => {},
    secrets: () => {
      secretRequests += 1;
    },
  });
  return { tree, commands, secretRequests: () => secretRequests };
}

/** What the user asked for by clicking the card, per the root contract. */
const intent = (state: ConnectionState) =>
  state === "missing_secret"
    ? "secrets"
    : state === "unresponsive"
      ? "reconnect"
      : active(state)
        ? "disconnect"
        : "connect";

const source = (path: string) =>
  readFileSync(new URL(path, import.meta.url), "utf8");

describe("intenção explícita do cartão de VPN", () => {
  // Red baseline: the card sent the legacy `toggle`, so a stale active snapshot
  // turned an already-off tunnel back on (and loaded secrets a second time).
  test("cada estado emite a intenção do usuário, nunca o toggle genérico", () => {
    for (const state of states) {
      const s = card(state);
      const expected = intent(state);
      // Disabled states are unreachable through the DOM; the handler contract
      // still has to name the user's direction, not the latest snapshot.
      if (state === "connecting" || state === "reconnecting") {
        expect(props(principal(s.tree)).onClick).toBeUndefined();
        click(principal(s.tree));
        expect(s.commands).toHaveLength(0);
        continue;
      }
      if (expected === "secrets") {
        click(principal(s.tree));
        expect(s.secretRequests()).toBe(0);
        const button = buttons(s.tree).find(
          (button) =>
            props(button)["aria-label"] ===
            `${profile.name}: ${t("providePassword")}`,
        );
        expect(button).toBeDefined();
        if (!button) throw new Error("Password switch missing");
        click(button);
      } else {
        click(principal(s.tree));
      }
      if (expected === "secrets") {
        expect(s.commands).toHaveLength(0);
        expect(s.secretRequests()).toBe(1);
      } else {
        expect(s.commands).toEqual([{ type: expected, id: profile.id }]);
        expect(s.commands[0].type).not.toBe("toggle");
        expect(s.secretRequests()).toBe(0);
      }
    }
  });

  test("cartões desabilitados seguem desabilitados e o rótulo/pressed continuam", () => {
    for (const state of states) {
      const button = principal(card(state).tree);
      if (
        state === "connecting" ||
        state === "reconnecting" ||
        state === "missing_secret"
      ) {
        expect(button.type).toBe("div");
        expect(props(button)["aria-pressed"]).toBeUndefined();
        continue;
      }
      expect(button.type).toBe("button");
      expect(props(button).disabled).toBe(
        [
          "offline",
          "helper_missing",
          "missing_program",
          "disconnecting",
        ].includes(state),
      );
      expect(props(button)["aria-pressed"]).toBe(active(state));
      expect(props(button)["aria-label"]).toBe(
        `${profile.name}: ${t(`state.${state}`)}`,
      );
    }
  });

  // Regression: the whole connecting card used to cancel; Cancel was only text.
  test("só Cancelar desliga durante conexão e reconexão", () => {
    for (const state of ["connecting", "reconnecting"] as const) {
      const s = card(state);
      const body = principal(s.tree);
      expect(body.type).toBe("div");
      expect(props(body).onClick).toBeUndefined();
      expect(props(body).tabIndex).toBeUndefined();
      click(body);
      expect(s.commands).toEqual([]);
      const cancel = buttons(s.tree);
      expect(cancel).toHaveLength(1);
      expect(props(cancel[0]).type).toBe("button");
      expect(props(cancel[0])["aria-label"]).toBe(t("cancel"));
      expect(props(cancel[0]).disabled).not.toBe(true);
      expect(props(cancel[0]).tabIndex).not.toBe(-1);
      click(cancel[0]);
      expect(s.commands).toEqual([{ type: "disconnect", id: profile.id }]);
    }
  });

  test("fora da espera o cartão preserva connect e disconnect", () => {
    for (const state of ["off", "connected"] as const) {
      const s = card(state);
      expect(principal(s.tree).type).toBe("button");
      click(principal(s.tree));
      expect(s.commands).toEqual([
        { type: state === "off" ? "connect" : "disconnect", id: profile.id },
      ]);
      expect(buttons(s.tree)).toHaveLength(1);
    }
  });

  test("os rótulos de espera, cancelar e o estado continuam iguais", () => {
    for (const state of states) {
      const text = textOf(card(state).tree);
      expect(text).toContain(t(`state.${state}`));
      if (state === "connecting" || state === "reconnecting")
        expect(text).toContain(t("cancel"));
    }
  });

  test("o botão Desligar do cartão sem resposta também emite disconnect", () => {
    const s = card("unresponsive");
    const matches = buttons(s.tree).filter(
      (button) => textOf(props(button).children) === t("disconnect"),
    );
    expect(matches).toHaveLength(1);
    click(matches[0]);
    expect(s.commands).toEqual([{ type: "disconnect", id: profile.id }]);
  });

  test("só o interruptor com nome acessível abre o diálogo de senha pendente", () => {
    const s = card("missing_secret");
    const text = textOf(s.tree);
    expect(text).toContain(t("state.missing_secret"));
    expect(text).not.toContain(t("secretHint"));
    expect(text).not.toContain(t("providePassword"));
    const body = principal(s.tree);
    expect(body.type).toBe("div");
    for (const attribute of [
      "type",
      "onClick",
      "tabIndex",
      "aria-label",
      "aria-pressed",
      "disabled",
    ])
      expect(props(body)[attribute]).toBeUndefined();
    click(body);
    expect(s.secretRequests()).toBe(0);
    const controls = buttons(s.tree);
    expect(controls).toHaveLength(1);
    const control = props(controls[0]);
    expect(control.type).toBe("button");
    expect(control.className).toContain("switch");
    expect(control["aria-label"]).toBe(
      `${profile.name}: ${t("providePassword")}`,
    );
    expect(control["aria-hidden"]).toBeUndefined();
    expect(control.disabled).not.toBe(true);
    click(controls[0]);
    expect(s.secretRequests()).toBe(1);
    expect(s.commands).toHaveLength(0);
  });

  // Static delta only: SecretsDialog owns React hooks, so invoking it outside a
  // renderer would invent a framework. Root verifies the sequence in WKWebView.
  test("o diálogo de segredo só conecta depois de salvar com sucesso", () => {
    const dialog = source("./components/SecretsDialog.tsx");
    expect(dialog).not.toContain('type: "toggle"');
    expect(dialog).toMatch(
      /if \(ok\)[\s\S]*if \(connect\)[\s\S]*type: "connect"/,
    );
  });

  test("o bridge trata connect/disconnect como comandos interativos", () => {
    const bridge = source("./bridge.ts");
    const list = bridge.match(/const interactive[^=]*=\s*\[([\s\S]*?)\]/)?.[1];
    expect(list).toBeDefined();
    for (const command of ['"toggle"', '"connect"', '"disconnect"'])
      expect(list).toContain(command);
  });
});
