import { describe, expect, test } from "bun:test";
import { resolveLocale, translate } from "./i18n";

describe("idioma da interface", () => {
  // Mutation captured: ignoring the preference makes English fall back to system Portuguese.
  test("a escolha explícita prevalece sobre o sistema", () => {
    expect(resolveLocale("en-US", ["pt-BR"])).toBe("en-US");
    expect(resolveLocale("pt-BR", ["en-US"])).toBe("pt-BR");
  });

  // Mutation captured: selecting the first unsupported language ignores a supported secondary one.
  test("o modo automático considera idiomas secundários antes do fallback", () => {
    expect(resolveLocale("system", ["de-DE", "pt-BR"])).toBe("pt-BR");
    expect(resolveLocale("system", ["fr-FR"])).toBe("en-US");
  });

  // Mutation captured: dropping interpolation hides which profile a destructive confirmation affects.
  test("a confirmação identifica o perfil selecionado nos dois idiomas", () => {
    const name = `VPN ${crypto.randomUUID()}`;
    for (const locale of ["pt-BR", "en-US"] as const) {
      const confirmation = translate(locale, "removeTitle", { name });
      expect(confirmation).toContain(name);
      expect(confirmation).not.toContain("{name}");
    }
  });
});
