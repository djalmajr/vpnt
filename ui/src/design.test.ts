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
