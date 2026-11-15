import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { createElement, isValidElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ComponentDialog } from "./components/ComponentDialog";
import type { T } from "./components/common";
import { translate } from "./i18n";
import type { Snapshot } from "./model";
import { Onboarding } from "./screens/Onboarding";
import { Preferences } from "./screens/Preferences";
import { defaultPreferences } from "./settings";

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
    test("installed version and Remove share one administrator row", () => {
      const html = renderToStaticMarkup(preferences());
      const lastGroup = html.slice(html.lastIndexOf('<section class="group">'));
      expect(lastGroup.match(/class="setting-row"/g)).toHaveLength(1);
      expect(lastGroup).toContain(t("helperInstalled"));
      expect(lastGroup).toContain(t("installedHint"));
      expect(lastGroup).toContain(snapshot.version);
      expect(lastGroup).toContain(`aria-label="${t("remove")}"`);
      expect(lastGroup).toContain(`title="${t("remove")}"`);
      expect(lastGroup).toContain('class="icon-button danger"');
      expect(lastGroup).toContain('viewBox="0 0 24 24"');
      expect(lastGroup).not.toContain(`>${t("remove")}<`);
      expect(lastGroup).not.toContain(
        locale === "en-US" ? "Remove component" : "Remover componente",
      );
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
