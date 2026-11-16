import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { T } from "./components/common";
import { translate } from "./i18n";
import type { VpnView } from "./model";
import { blankProfile } from "./profileDefaults";
import { Profile } from "./screens/Profile";
import { hasShellExpression } from "./shellExpression";

const fixture = (kind: "ipsec" | "ssl", username = "fixture"): VpnView => ({
  profile: {
    ...blankProfile(kind),
    name: "FixtureVPN",
    gateway: "vpn.example.test",
    probeHost: "192.0.2.1",
    username,
  },
  state: "off",
  cleaning: false,
  hasPassword: false,
  hasPsk: false,
  log: [],
});

for (const locale of ["pt-BR", "en-US"] as const) {
  const t: T = (key, values) => translate(locale, key, values);
  const render = (vpn: VpnView) =>
    renderToStaticMarkup(
      createElement(Profile, {
        vpn,
        t,
        navigate: () => {},
        registerNavigationGuard: () => {},
        saved: () => {},
        run: async () => true,
        secrets: () => {},
        remove: () => {},
      }),
    );
  test(`${locale}: um botão de segredos no IPsec e SSL, conforme status aplicável`, () => {
    for (const kind of ["ipsec", "ssl"] as const) {
      for (const hasPassword of [false, true]) {
        for (const hasPsk of [false, true]) {
          const html = render({ ...fixture(kind), hasPassword, hasPsk });
          const section = html.slice(
            html.indexOf(`<h2 class="section-title">${t("secrets")}`),
          );
          const controls = section.slice(0, section.indexOf("</section>"));
          expect(controls.match(/<button/g)).toHaveLength(1);
          expect(controls).toContain(
            `>${t(hasPassword || (kind === "ipsec" && hasPsk) ? "change" : "provide")}<`,
          );
          expect(controls).toContain(t(hasPassword ? "stored" : "notStored"));
          expect(controls.match(/class="setting-row"/g)).toHaveLength(
            kind === "ipsec" ? 2 : 1,
          );
        }
      }
    }
  });
  test(`${locale}: expressão de shell no usuário mostra erro associado e bloqueia salvar`, () => {
    for (const username of [
      // biome-ignore lint/suspicious/noTemplateCurlyInString: The fixture is intentionally literal shell syntax.
      "${VPN_USER:-fixture}",
      "$(whoami)",
      "`whoami`",
      "literal-user",
    ]) {
      const html = render(fixture("ipsec", username));
      const invalid = username !== "literal-user";
      expect(html.includes(t("usernameShellError"))).toBe(invalid);
      expect(html.includes('aria-invalid="true"')).toBe(invalid);
      expect(html.includes('type="submit" class="primary" disabled=""')).toBe(
        invalid,
      );
      if (invalid) {
        const id = html.match(/aria-describedby="([^"]+)"/)?.[1];
        expect(id).toBeTruthy();
        expect(html).toContain(
          `id="${id}" class="field-error danger-text" role="alert"`,
        );
      }
    }
  });
}

test("detecção de shell reconhece os três padrões sem rejeitar dólar literal", () => {
  // biome-ignore lint/suspicious/noTemplateCurlyInString: Detection requires a literal placeholder, never interpolation.
  for (const value of ["${USER}", "prefix$(cmd)", "`x`", "abc${", "$("])
    expect(hasShellExpression(value)).toBe(true);
  for (const value of ["", "u.ser", "$literal", "cash$", "a(b)", "{name}"])
    expect(hasShellExpression(value)).toBe(false);
});
