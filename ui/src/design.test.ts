import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

// Mutation captured: a self-referencing field width silently falls back to auto and breaks column alignment.
test("tokens geométricos não podem formar referências diretas a si mesmos", () => {
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  const declarations = [...css.matchAll(/(--[\w-]+):\s*([^;]+);/g)];
  for (const [, name, value] of declarations) {
    expect(value, `${name} has a CSS variable cycle`).not.toMatch(
      new RegExp(`var\\(\\s*${name}\\s*[,)]`),
    );
  }
});

// The scrolling surface must stop above the footer, including short windows.
test("rodapé reserva espaço fora da superfície rolável e usa texto pequeno", () => {
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  const block = (selector: string) => {
    const declarations = css.split(`${selector} {`).slice(1);
    expect(declarations.length, selector).toBeGreaterThan(0);
    return declarations.map((part) => part.split("}")[0]).join("\n");
  };
  expect(block(".panel")).toContain(
    "max-height: min(100vh, var(--panel-max-height))",
  );
  expect(block(".panel")).toContain("overflow: hidden");
  expect(block(".panel-content")).toContain("overflow: auto");
  expect(block(".panel-content")).toContain("min-height: 0");
  expect(block(".footer")).toContain("flex-shrink: 0");
  expect(block(".footer > small")).toContain("font-size: var(--font-control)");
});
