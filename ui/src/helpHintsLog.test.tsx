import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { Help, helpEscape, type T } from "./components/common";
import { translate } from "./i18n";
import type { Snapshot, VpnView } from "./model";
import { Log } from "./screens/Log";
import { Preferences } from "./screens/Preferences";
import { defaultPreferences, defaultSettings } from "./settings";

const vpn = (id: string): VpnView => ({
  profile: {
    id,
    name: `Fixture ${id}`,
    kind: "ipsec",
    gateway: "vpn.example.test",
    username: "fixture",
    networks: ["192.0.2.0/24"],
    port: 500,
    certificate: "",
    probeHost: "192.0.2.1",
    probePort: 8443,
    probeMethod: "ping_tcp",
  },
  state: "off",
  cleaning: false,
  hasPassword: false,
  hasPsk: false,
  log: [{ timestamp: 1, state: "off" }],
});
const snapshot: Snapshot = {
  version: "0.1.0",
  demo: false,
  helper: "installed",
  preferences: defaultPreferences,
  vpns: [],
};

for (const locale of ["pt-BR", "en-US"] as const) {
  const t: T = (key, values) => translate(locale, key, values);
  describe(`dicas e abas: ${locale}`, () => {
    // SSR protects the requested rows and names, not runtime focus or layout.
    test("somente as quatro linhas pedidas têm dicas com nome traduzido", () => {
      for (const helper of ["installed", "missing", "outdated"] as const) {
        const html = renderToStaticMarkup(
          createElement(Preferences, {
            snapshot: { ...snapshot, helper },
            settings: {
              ...defaultPreferences,
              ...defaultSettings,
              preferencesPending: false,
            },
            update: () => {},
            navigate: () => {},
            removeComponent: () => {},
            t,
          }),
        );
        const rows = html.split('<div class="setting-row">').slice(1);
        const required = [
          ["testEvery", "testEveryHelp"],
          ["notifyStale", "notifyStaleHelp"],
          ["autoReconnect", "autoReconnectHelp"],
          [
            helper === "installed" ? "helperInstalled" : "helperMissing",
            "componentHelp",
          ],
        ] as const;
        expect(html.match(/class="help-trigger"/g)).toHaveLength(4);
        for (const [label, help] of required) {
          const row = rows.find((row) => row.includes(t(label)));
          expect(row).toContain(
            `role="img" tabindex="0" aria-label="${t(help)}"`,
          );
        }
        for (const label of ["startAtLogin", "language", "theme"] as const) {
          const row = rows.find((row) => row.includes(t(label)));
          expect(row).toBeDefined();
          expect(row).not.toContain('class="help-trigger"');
        }
        for (const hint of html.matchAll(
          /<span[^>]*class="help-trigger"[^>]*>/g,
        ))
          expect(hint[0]).not.toContain('title="');
      }
    });
    test("Help expõe a dica inteira como nome e não usa title", () => {
      const text = t("componentHelp");
      const html = renderToStaticMarkup(createElement(Help, { text }));
      expect(html).toContain(`aria-label="${text}"`);
      expect(html).toContain('role="img" tabindex="0"');
      expect(html).not.toContain('title="');
    });
    const log = (count: number, id?: string) =>
      renderToStaticMarkup(
        createElement(Log, {
          snapshot: {
            ...snapshot,
            vpns: [vpn("one"), vpn("two")].slice(0, count),
          },
          id,
          navigate: () => {},
          run: async () => true,
          t,
          locale,
        }),
      );
    test("uma VPN usa texto sem tablist e nomeia o painel por esse texto", () => {
      const html = log(1, "removed-profile");
      expect(html).not.toContain('role="tablist"');
      expect(html).not.toContain('role="tab"');
      const label = html.match(
        /<strong id="([^"]+)">Fixture one<\/strong>/,
      )?.[1];
      expect(label).toBeDefined();
      expect(html).toContain(`role="tabpanel" aria-labelledby="${label}"`);
    });
    test("duas VPNs mantêm abas e relação entre seleção e painel", () => {
      const html = log(2, "two");
      expect(html).toContain('role="tablist"');
      expect(html.match(/role="tab"/g)).toHaveLength(2);
      const selected = html.match(
        /role="tab" id="([^"]+)" aria-controls="([^"]+)" aria-selected="true" tabindex="0"/,
      );
      expect(selected).not.toBeNull();
      expect(html).toContain(
        `id="${selected?.[2]}" role="tabpanel" aria-labelledby="${selected?.[1]}"`,
      );
      expect(html).toContain('aria-selected="false" tabindex="-1"');
    });
    test("copiar fica na linha do perfil ou abas, fora do tablist e do rodapé", () => {
      for (const count of [1, 2]) {
        const html = log(count, "two");
        const headingStart = html.indexOf('<div class="log-heading">');
        const panelStart = html.lastIndexOf(
          "<div",
          html.indexOf('role="tabpanel"'),
        );
        expect(headingStart).toBeGreaterThan(-1);
        const heading = html.slice(headingStart, panelStart);
        const copy = heading
          .match(/<button[^>]*aria-label="([^"]+)"[^>]*>[\s\S]*?<\/button>/g)
          ?.find((button) => button.includes(`aria-label="${t("copy")}"`));
        expect(copy).toBeDefined();
        expect(copy).toContain('class="icon-button"');
        expect(copy).toContain(`title="${t("copy")}"`);
        expect(copy).toContain('viewBox="0 0 24 24"');
        expect(copy).not.toContain(`>${t("copy")}<`);
        expect(
          html.match(new RegExp(`aria-label="${t("copy")}"`, "g")),
        ).toHaveLength(1);
        if (count === 1) {
          expect(heading).toContain(">Fixture one</strong>");
          expect(heading.indexOf("</strong>")).toBeLessThan(
            heading.indexOf(`aria-label="${t("copy")}"`),
          );
        } else {
          const tablist = heading.slice(
            heading.indexOf('role="tablist"'),
            heading.indexOf("</div>"),
          );
          expect(tablist.match(/role="tab"/g)).toHaveLength(2);
          expect(tablist).not.toContain(`aria-label="${t("copy")}"`);
          expect(heading.indexOf("</div>")).toBeLessThan(
            heading.indexOf(`aria-label="${t("copy")}"`),
          );
        }
        const footer = html.slice(html.indexOf('<div class="spread">'));
        expect(footer).toContain(t("lastLines"));
        expect(footer).not.toContain("<button");
      }
    });
    test("sem VPN o painel conserva um nome acessível", () => {
      const html = log(0);
      expect(html).not.toContain('role="tablist"');
      expect(html).not.toContain("aria-labelledby=");
      expect(html).toContain(`role="tabpanel" aria-label="${t("log")}"`);
    });
  });
}

// Mutation captured: letting Escape reach the document listener hid the whole
// native popover when the user only wanted to dismiss the hint.
test("Escape com a dica aberta fecha só a dica e não chega ao atalho global", () => {
  const calls: string[] = [];
  const event = (key: string) => ({
    key,
    preventDefault: () => calls.push(`prevent:${key}`),
    stopImmediatePropagation: () => calls.push(`stop:${key}`),
  });
  const handler = helpEscape(() => calls.push("close"));
  handler(event("Tab"));
  expect(calls).toEqual([]);
  handler(event("Escape"));
  expect(calls).toEqual(["prevent:Escape", "stop:Escape", "close"]);
});
