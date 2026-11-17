import { describe, expect, test } from "bun:test";
import { blankProfile } from "./profileDefaults";

// Guarda de regressão: o tipo do perfil decide a porta remota padrão que o
// backend consome como remote_port (IKE 500 no IPsec, 443 no SSL).
describe("padrões do novo perfil", () => {
  test("IPsec nasce com porta remota 500", () => {
    expect(blankProfile("ipsec").port).toBe(500);
  });

  test("SSL continua nascendo com porta 443", () => {
    expect(blankProfile("ssl").port).toBe(443);
  });

  test("o tipo pedido é preservado", () => {
    expect(blankProfile("ipsec").kind).toBe("ipsec");
    expect(blankProfile("ssl").kind).toBe("ssl");
  });

  test("os demais padrões do DTO não mudam", () => {
    for (const kind of ["ipsec", "ssl"] as const) {
      const profile = blankProfile(kind);
      expect(profile.name).toBe("");
      expect(profile.gateway).toBe("");
      expect(profile.username).toBe("");
      expect(profile.networks).toEqual([]);
      expect(profile.certificate).toBe("");
      expect(profile.probeHost).toBe("");
      expect(profile.probePort).toBe(8443);
      expect(profile.probeMethod).toBe("ping_tcp");
    }
  });

  test("o id é hexadecimal minúsculo de 32 caracteres e não se repete", () => {
    const first = blankProfile("ipsec");
    const second = blankProfile("ipsec");
    for (const profile of [first, second]) {
      expect(profile.id).toMatch(/^[0-9a-f]{32}$/);
    }
    expect(first.id).not.toBe(second.id);
  });

  test("cada perfil recebe a própria lista de redes", () => {
    const first = blankProfile("ipsec");
    first.networks.push("10.20.0.0/24");
    expect(blankProfile("ipsec").networks).toEqual([]);
  });
});
