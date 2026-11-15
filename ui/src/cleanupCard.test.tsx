import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { T } from "./components/common";
import { VpnCard } from "./components/VpnCard";
import { translate } from "./i18n";
import type { VpnView } from "./model";

for (const locale of ["pt-BR", "en-US"] as const) {
  for (const state of [
    "gateway_timeout",
    "credentials_rejected",
    "dropped",
    "missing_program",
  ] as const) {
    test(`${locale} ${state}: cleanup keeps the failure visible and disables actions until complete`, () => {
      const t: T = (key, values) => translate(locale, key, values);
      const vpn: VpnView = {
        profile: {
          id: "fixture",
          name: "Fixture",
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
        state,
        cleaning: true,
        hasPassword: true,
        hasPsk: true,
        log: [],
      };
      const render = (cleaning: boolean) =>
        renderToStaticMarkup(
          createElement(VpnCard, {
            vpn: { ...vpn, cleaning },
            t,
            run: async () => true,
            navigate: () => {},
            secrets: () => {},
          }),
        );
      const pending = render(true);
      expect(pending).toContain(t(`state.${state}`));
      expect(pending).toContain(t("cleanupHint"));
      expect(pending).not.toContain(t("state.disconnecting"));
      expect(pending).not.toContain(`>${t("disconnect")}<`);
      expect(pending).toMatch(/disabled=""[^>]*class="switch[^"]*"/);
      // The Notice action stays in the tab order, inert and described by the
      // cleanup status instead of natively disabled.
      const id = pending.match(/<p id="([^"]+)" role="status">/)?.[1];
      expect(id).toBeTruthy();
      expect(pending).toContain(
        `${state === "missing_program" ? 'type="button"' : 'class="primary"'} aria-disabled="true" aria-describedby="${id}"`,
      );
      expect(pending).not.toMatch(/class="primary" disabled=""/);
      const ready = render(false);
      expect(ready).toContain(t(`state.${state}`));
      expect(ready).not.toContain(t("cleanupHint"));
      if (state !== "missing_program")
        expect(ready).not.toMatch(/disabled=""[^>]*class="switch[^"]*"/);
      expect(ready).not.toMatch(/class="primary" disabled=""/);
      expect(ready).not.toContain("aria-disabled");
    });
  }
}
