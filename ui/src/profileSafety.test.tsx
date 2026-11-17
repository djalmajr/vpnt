import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { T } from "./components/common";
import { VpnCard } from "./components/VpnCard";
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
  cleanupVerifying: false,
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
  test(`${locale}: o cartão distingue redes do gateway de túnel completo`, () => {
    const label = locale === "pt-BR" ? "Rotas do gateway" : "Gateway routes";
    const full = locale === "pt-BR" ? "Túnel completo" : "Full tunnel";
    const card = (vpn: VpnView) =>
      renderToStaticMarkup(
        createElement(VpnCard, {
          vpn,
          t,
          run: async () => true,
          navigate: () => {},
          secrets: () => {},
        }),
      );
    const ssl = card(fixture("ssl"));
    expect(ssl).toContain(label);
    expect(ssl).not.toContain(full);
    const ipsec = card(fixture("ipsec"));
    expect(ipsec).toContain(full);
    expect(ipsec).not.toContain(label);
    for (const kind of ["ssl", "ipsec"] as const) {
      const vpn = fixture(kind);
      vpn.profile.networks = ["10.0.0.0/8", "192.168.0.0/16"];
      const explicit = card(vpn);
      expect(explicit).toContain("10.0.0.0/8, 192.168.0.0/16");
      expect(explicit).not.toContain(label);
      expect(explicit).not.toContain(full);
    }
  });
  test(`${locale}: formulário mostra a dica de redes própria de cada tipo`, () => {
    const gatewayHint =
      locale === "pt-BR"
        ? "Só estas redes passam pelo túnel. Vazio: as rotas que o gateway publica."
        : "Only these networks use the tunnel. Empty: the routes the gateway publishes.";
    const fullHint =
      locale === "pt-BR"
        ? "Só estas redes passam pelo túnel. Vazio: túnel completo."
        : "Only these networks use the tunnel. Empty: full tunnel.";
    const ssl = render(fixture("ssl"));
    expect(ssl).toContain(gatewayHint);
    expect(ssl).not.toContain(fullHint);
    expect(ssl).toContain('placeholder="10.20.0.0/24"');
    expect(ssl).toContain(t("certificateHint"));
    const ipsec = render(fixture("ipsec"));
    expect(ipsec).toContain(fullHint);
    expect(ipsec).not.toContain(gatewayHint);
    expect(ipsec).toContain('placeholder="10.20.0.0/24"');
  });
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
