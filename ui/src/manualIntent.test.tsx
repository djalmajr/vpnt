import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { isValidElement, type ReactElement, type ReactNode } from "react";
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

const view = (state: ConnectionState): VpnView => ({
  profile,
  state,
  cleaning: false,
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
    if (String(props(element).className).split(" ").includes("switch"))
      matches.push(element);
  });
  expect(matches).toHaveLength(1);
  return matches[0];
}

function click(element: ReactElement) {
  const handler = props(element).onClick;
  if (typeof handler === "function") (handler as () => void)();
}

function card(
  state: ConnectionState,
  cleaning = false,
  locale: "pt-BR" | "en-US" = "pt-BR",
) {
  const commands: Command[] = [];
  const routes: unknown[] = [];
  let secretRequests = 0;
  const run: Run = async (command) => {
    commands.push(command);
    return true;
  };
  const tree = VpnCard({
    vpn: { ...view(state), cleaning },
    t: (key, values) => translate(locale, key, values),
    run,
    navigate: (route) => {
      routes.push(route);
    },
    secrets: () => {
      secretRequests += 1;
    },
  });
  return { tree, commands, routes, secretRequests: () => secretRequests };
}

const source = (path: string) =>
  readFileSync(new URL(path, import.meta.url), "utf8");

// The simulated DOM fixture also exercises descendants; this invokes the handler.
function bubble(tree: ReactElement, control = false) {
  const handler = props(tree).onClick as (event: unknown) => void;
  handler({ target: { closest: () => (control ? {} : null) } });
}

for (const locale of ["pt-BR", "en-US"] as const) {
  describe(`intenção explícita do interruptor: ${locale}`, () => {
    test("cada estado emite a direção exibida; espera e limpeza ficam inertes", () => {
      for (const state of states) {
        for (const cleaning of [false, true]) {
          const s = card(state, cleaning, locale);
          const control = principal(s.tree);
          const disabled =
            cleaning ||
            [
              "offline",
              "helper_missing",
              "missing_program",
              "disconnecting",
              "connecting",
              "reconnecting",
            ].includes(state);
          expect(control.type).toBe("button");
          expect(props(control).disabled).toBe(disabled);
          expect(props(control)["aria-pressed"]).toBe(active(state));
          expect(props(control)["aria-label"]).toBe(
            `${profile.name}: ${translate(locale, `state.${state}`)}`,
          );
          click(control);
          bubble(s.tree, true);
          expect(s.routes).toEqual([]);
          expect(s.commands).toEqual(
            disabled || state === "missing_secret"
              ? []
              : [
                  {
                    type: active(state) ? "disconnect" : "connect",
                    id: profile.id,
                  },
                ],
          );
          expect(s.secretRequests()).toBe(
            !disabled && state === "missing_secret" ? 1 : 0,
          );
        }
      }
    });
    test("corpo e chevron abrem detalhes sem conectar, inclusive durante espera", () => {
      for (const state of states) {
        const s = card(state, false, locale);
        bubble(s.tree);
        expect(s.routes).toEqual([{ page: "profile", id: profile.id }]);
        const details = buttons(s.tree).find(
          (button) =>
            props(button)["aria-label"] ===
            translate(locale, "profileDetails", { name: profile.name }),
        );
        expect(details).toBeDefined();
        if (!details) throw new Error("Details button missing");
        click(details);
        bubble(s.tree, true);
        expect(s.routes).toEqual([
          { page: "profile", id: profile.id },
          { page: "profile", id: profile.id },
        ]);
        expect(s.commands).toEqual([]);
        expect(s.secretRequests()).toBe(0);
      }
    });
    test("só Cancelar cancela conexão/reconexão, sem navegar", () => {
      for (const state of ["connecting", "reconnecting"] as const) {
        const s = card(state, false, locale);
        click(principal(s.tree));
        expect(s.commands).toEqual([]);
        const cancel = buttons(s.tree).find(
          (button) =>
            props(button)["aria-label"] === translate(locale, "cancel"),
        );
        expect(cancel).toBeDefined();
        if (!cancel) throw new Error("Cancel missing");
        click(cancel);
        bubble(s.tree, true);
        expect(s.commands).toEqual([{ type: "disconnect", id: profile.id }]);
        expect(s.routes).toEqual([]);
      }
    });
    test("Notice não abre o perfil e conserva reconectar", () => {
      const s = card("unresponsive", false, locale);
      const reconnect = buttons(s.tree).find(
        (button) =>
          textOf(props(button).children) === translate(locale, "reconnect"),
      );
      expect(reconnect).toBeDefined();
      if (!reconnect) throw new Error("Reconnect missing");
      click(reconnect);
      bubble(s.tree, true);
      expect(s.commands).toEqual([{ type: "reconnect", id: profile.id }]);
      expect(s.routes).toEqual([]);
    });
    test("senha pendente só oferece o switch e detalhes, sem aviso extra", () => {
      const s = card("missing_secret", false, locale);
      expect(buttons(s.tree)).toHaveLength(2);
      expect(textOf(s.tree)).not.toContain(translate(locale, "secretHint"));
      click(principal(s.tree));
      expect(s.secretRequests()).toBe(1);
      expect(s.commands).toEqual([]);
    });
  });
}

describe("sequência dos comandos interativos", () => {
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
