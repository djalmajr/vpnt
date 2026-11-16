import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { createElement, isValidElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  ComponentDialog,
  ComponentDialogBody,
} from "./components/ComponentDialog";
import type { T } from "./components/common";
import { RemoveDialogBody } from "./components/RemoveDialog";
import { translate } from "./i18n";
import type { Snapshot } from "./model";
import { Onboarding } from "./screens/Onboarding";
import { Preferences } from "./screens/Preferences";
import { defaultPreferences } from "./settings";

/** The spinner must live inside the busy primary button: nowhere else. */
function expectSpinnerOnlyInPrimary(html: string, cls: string, label: string) {
  const button = html.match(
    new RegExp(`<button[^>]*class="${cls}"[^>]*>[\\s\\S]*?</button>`),
  )?.[0];
  expect(button).toBeDefined();
  const primary = button ?? "";
  const open = primary.slice(0, primary.indexOf(">") + 1);
  expect(open).toContain("disabled");
  expect(open).toContain('aria-busy="true"');
  expect(primary).toContain(' spin"');
  expect(primary.indexOf("<svg")).toBeLessThan(primary.indexOf(`>${label}<`));
  expect(html.split("<svg").length - 1).toBe(1);
  expect(html.replace(primary, "")).not.toContain("<svg");
  expect(html.replace(primary, "")).not.toContain("aria-busy");
}

const snapshot: Snapshot = {
  version: "0.1.0",
  demo: false,
  helper: "installed",
  preferences: defaultPreferences,
  vpns: [],
};
const settings = {
  ...defaultPreferences,
  locale: "system" as const,
  theme: "system" as const,
  preferencesPending: false,
};
const source = (path: string) =>
  readFileSync(new URL(path, import.meta.url), "utf8");
function buttons(node: ReactNode): Record<string, unknown>[] {
  if (Array.isArray(node)) return node.flatMap(buttons);
  if (!isValidElement<{ children?: ReactNode }>(node)) return [];
  return [
    ...(node.type === "button" ? [node.props] : []),
    ...buttons(node.props.children),
  ];
}

for (const locale of ["pt-BR", "en-US"] as const) {
  const t: T = (key, values) => translate(locale, key, values);
  const preferences = (removeComponent = () => {}, busy = false) =>
    Preferences({
      snapshot: {
        ...snapshot,
        componentOperation: busy ? "removing" : undefined,
      },
      settings,
      update: () => {},
      navigate: () => {},
      removeComponent,
      t,
    });
  describe(`component UI: ${locale}`, () => {
    test("outdated onboarding and confirmation use the update action", () => {
      let opens = 0;
      const onboarding = Onboarding({
        navigate: () => {},
        install: () => {
          opens += 1;
        },
        busy: false,
        outdated: true,
        t,
      });
      expect(renderToStaticMarkup(onboarding)).toContain(t("helperOutdated"));
      const action = buttons(onboarding).find(
        (button) => button.children === t("update"),
      );
      expect(action).toBeDefined();
      if (typeof action?.onClick !== "function")
        throw new Error("missing update action");
      action.onClick();
      expect(opens).toBe(1);
      let confirms = 0;
      const body = ComponentDialogBody({
        kind: "install",
        updating: true,
        pending: false,
        confirm: () => {
          confirms += 1;
        },
        close: () => {},
        t,
      });
      expect(renderToStaticMarkup(body)).toContain(t("componentUpdateHint"));
      const confirm = buttons(body).find(
        (button) =>
          Array.isArray(button.children) &&
          button.children.includes(t("update")),
      );
      expect(confirm).toBeDefined();
      if (typeof confirm?.onClick !== "function")
        throw new Error("missing confirmation action");
      confirm.onClick();
      expect(confirms).toBe(1);
    });
    test("installed version and Remove share one administrator row", () => {
      const html = renderToStaticMarkup(preferences());
      const lastGroup = html.slice(html.lastIndexOf('<section class="group">'));
      expect(lastGroup.match(/setting-row/g)).toHaveLength(1);
      expect(lastGroup).toContain('class="setting-row component-row"');
      expect(lastGroup).toContain(t("helperInstalled"));
      expect(lastGroup).toContain(t("installedHint"));
      expect(lastGroup).toContain(snapshot.version);
      expect(lastGroup).toContain(`aria-label="${t("remove")}"`);
      expect(lastGroup).toContain(`title="${t("remove")}"`);
      expect(lastGroup).toContain('class="icon-button component-remove"');
      expect(lastGroup).not.toContain('class="icon-button danger"');
      expect(lastGroup).toContain('viewBox="0 0 24 24"');
      expect(lastGroup).not.toContain(`>${t("remove")}<`);
      expect(lastGroup).not.toContain(
        locale === "en-US" ? "Remove component" : "Remover componente",
      );
    });
    test("versão acompanha título e lixeira ocupa as duas linhas", () => {
      const html = renderToStaticMarkup(preferences());
      const lastGroup = html.slice(html.lastIndexOf('<section class="group">'));
      expect(lastGroup).toContain('class="component-version"');
      expect(lastGroup).toContain('class="icon-button component-remove"');
      expect(lastGroup).toContain('class="component-hint"');
      const css = source("./styles.css");
      expect(css).toMatch(
        /\.setting-row\.component-row\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1fr\) auto auto/s,
      );
      expect(css).toMatch(
        /\.component-version\s*\{[^}]*grid-area:\s*1\s*\/\s*2/s,
      );
      expect(css).toMatch(
        /\.component-remove\s*\{[^}]*grid-area:\s*1\s*\/\s*3\s*\/\s*3/s,
      );
      expect(css).toMatch(/\.component-hint\s*\{[^}]*grid-area:\s*2\s*\/\s*1/s);
    });
    for (const kind of ["install", "remove"] as const) {
      test(`ComponentDialog ${kind}: espera com spinner dentro do primário`, () => {
        const pending = renderToStaticMarkup(
          createElement(ComponentDialogBody, {
            kind,
            pending: true,
            confirm: () => {},
            close: () => {},
            t,
          }),
        );
        const [text, actions] = pending.split('<div class="actions end">');
        expect(text).toContain(
          t(
            kind === "install"
              ? "componentInstallPending"
              : "componentRemovePending",
          ),
        );
        expect(text).not.toContain("<svg");
        expect(actions).toBeDefined();
        expectSpinnerOnlyInPrimary(
          pending,
          kind === "install" ? "primary" : "danger-fill",
          t(kind === "install" ? "install" : "remove"),
        );
        const idle = renderToStaticMarkup(
          createElement(ComponentDialogBody, {
            kind,
            pending: false,
            confirm: () => {},
            close: () => {},
            t,
          }),
        );
        expect(idle).toContain(
          t(
            kind === "install" ? "componentInstallHint" : "componentRemoveHint",
          ),
        );
        expect(idle).not.toContain("<svg");
        expect(idle).not.toContain("aria-busy");
        expect(idle).not.toContain("disabled");
      });
    }
    test("RemoveDialog: espera com spinner dentro do Remover", () => {
      const saving = renderToStaticMarkup(
        createElement(RemoveDialogBody, {
          saving: true,
          confirm: () => {},
          close: () => {},
          t,
        }),
      );
      const [text, actions] = saving.split('<div class="actions end">');
      expect(text).toContain(t("adminPending"));
      expect(text).not.toContain("<svg");
      expect(actions).toBeDefined();
      expectSpinnerOnlyInPrimary(saving, "danger-fill", t("remove"));
      const idle = renderToStaticMarkup(
        createElement(RemoveDialogBody, {
          saving: false,
          confirm: () => {},
          close: () => {},
          t,
        }),
      );
      expect(idle).toContain(t("removeHint"));
      expect(idle).not.toContain("<svg");
      expect(idle).not.toContain("aria-busy");
      expect(idle).not.toContain("disabled");
    });
    test("lista e Add VPN guardam origem Preferências", () => {
      const routes: unknown[] = [];
      const profile = {
        id: "fixture",
        name: "Fixture",
        kind: "ssl" as const,
        gateway: "vpn.example.test",
        username: "fixture",
        networks: [],
        port: 443,
        certificate: "",
        probeHost: "192.0.2.1",
        probePort: 443,
        probeMethod: "tcp" as const,
      };
      const tree = Preferences({
        snapshot: {
          ...snapshot,
          vpns: [
            {
              profile,
              state: "off",
              cleaning: false,
              hasPassword: false,
              hasPsk: false,
              log: [],
            },
          ],
        },
        settings,
        update: () => {},
        navigate: (route) => routes.push(route),
        removeComponent: () => {},
        t,
      });
      const row = buttons(tree).find(
        (button) => button.className === "profile-row",
      );
      const add = buttons(tree).find(
        (button) => button.className === "link add-profile",
      );
      expect(row).toBeDefined();
      expect(add).toBeDefined();
      if (!row || !add) throw new Error("Profile controls missing");
      (row.onClick as () => void)();
      (add.onClick as () => void)();
      expect(routes).toEqual([
        { page: "profile", id: "fixture", origin: "preferences" },
        { page: "new", origin: "preferences" },
      ]);
    });
    test("Remove requests confirmation without sending a command", () => {
      let confirmations = 0;
      const remove = buttons(preferences(() => confirmations++)).find(
        (button) => button["aria-label"] === t("remove"),
      );
      expect(remove).toBeDefined();
      expect(confirmations).toBe(0);
      if (!remove) throw new Error("Remove button missing");
      (remove.onClick as () => void)();
      expect(confirmations).toBe(1);
      expect(
        buttons(preferences(() => {}, true)).find(
          (button) => button["aria-label"] === t("remove"),
        )?.disabled,
      ).toBe(true);
    });
    test("onboarding has only a full width Install action", () => {
      const html = renderToStaticMarkup(
        createElement(Onboarding, {
          t,
          navigate: () => {},
          install: () => {},
          busy: false,
        }),
      );
      const actions = html.slice(html.indexOf('<div class="actions fill">'));
      expect(actions.match(/<button/g)).toHaveLength(1);
      expect(actions).toContain(t("install"));
      expect(html).not.toContain(
        locale === "en-US" ? "View details" : "Ver detalhes",
      );
      const busy = renderToStaticMarkup(
        createElement(Onboarding, {
          t,
          navigate: () => {},
          install: () => {},
          busy: true,
        }),
      );
      expect(busy).toContain(t("componentSettling"));
      expect(busy).not.toContain('class="actions fill"');
    });
    test("removal renders its own confirmation before running", () => {
      let commands = 0;
      const html = renderToStaticMarkup(
        createElement(ComponentDialog, {
          kind: "remove",
          t,
          run: async () => {
            commands++;
            return true;
          },
          close: () => {},
          installed: () => {},
        }),
      );
      expect(html).toContain(t("componentRemoveTitle"));
      expect(html).toContain(t("componentRemoveHint"));
      expect(html).toContain('class="danger-fill"');
      expect(html).toContain('aria-busy="false"');
      expect(commands).toBe(0);
    });
  });
}

// Static wiring guards complement the DOM fixture receipt. SSR does not run
// effects or prove layout, top-layer placement, focus, scrolling, or WebKit.
test("App wires Preferences Remove to ComponentDialog remove", () => {
  const app = source("./App.tsx");
  expect(app).toContain('removeComponent={() => setComponentAction("remove")}');
  expect(app).toMatch(
    /componentAction &&[\s\S]*<ComponentDialog[\s\S]*kind={componentAction}/,
  );
});
