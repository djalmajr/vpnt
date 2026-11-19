import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { Icon } from "./components/common";

test("loader tem anel, arco e rotação central", () => {
  const html = renderToStaticMarkup(createElement(Icon, { name: "loader" }));
  expect(html).toContain('viewBox="0 0 24 24"');
  expect(html).toContain('cx="12" cy="12" r="9"');
  expect(html).toContain('class="loader-track"');
  expect(html).toContain('d="M12 3a9 9 0 0 1 9 9"');
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  expect(css).toMatch(/--icon-spinner:\s*14px\s*;/);
  expect(css).toMatch(/\.spin\s*\{[^}]*display:\s*block/s);
  expect(css).toMatch(/\.spin\s*\{[^}]*flex:\s*none/s);
  expect(css).toMatch(/\.spin\s*\{[^}]*transform-origin:\s*50%\s+50%/s);
  expect(css).toMatch(/\.spin\s*\{[^}]*transform-box:\s*border-box/s);
  expect(css).not.toMatch(/\.spin\s*\{[^}]*transform-box:\s*view-box/s);
  expect(css).toMatch(/\.icon\.spin\s*\{[^}]*width:\s*var\(--icon-spinner\)/s);
  expect(css).toMatch(/\.icon\.spin\s*\{[^}]*height:\s*var\(--icon-spinner\)/s);
  expect(css.indexOf(".icon.spin")).toBeGreaterThan(css.indexOf(".icon.large"));
  expect(css).toMatch(
    /button:has\(>\s*\.spin\)\s*\{[^}]*display:\s*inline-flex/s,
  );
  expect(css).toMatch(
    /\.loader-track\s*\{[^}]*opacity:\s*var\(--dim-opacity\)/s,
  );
  expect(css).toMatch(
    /prefers-reduced-motion:\s*reduce[\s\S]*?\.spin\s*\{\s*animation:\s*none/,
  );
});

test("trilho segmentado usa papéis neutros, não a cor primária", () => {
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  expect(css).toMatch(/\.tabs\s*\{[^}]*background:\s*var\(--control\)/s);
  expect(css).toMatch(
    /\.tabs\s*>\s*\[role="tab"\]\s*\{[^}]*color:\s*var\(--secondary\)/s,
  );
  expect(css).toMatch(
    /\.tabs\s*>\s*\[role="tab"\]\[aria-selected="true"\]\s*\{[^}]*background:\s*var\(--surface\)/s,
  );
  expect(css).toMatch(
    /\.tabs\s*>\s*\[role="tab"\]\[aria-selected="true"\]\s*\{[^}]*color:\s*var\(--text\)/s,
  );
});

// Mutation captured: overflow-x: auto on the track showed a scrollbar and clipped the second profile.
test("trilho segmentado encolhe os nomes com reticências, sem rolagem", () => {
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  const track = css.match(/\.tabs\s*\{([^}]*)\}/s)?.[1] ?? "";
  expect(track).toContain("overflow: hidden");
  expect(track).not.toMatch(/overflow(-x)?:\s*(auto|scroll)/);
  const segment =
    css.match(/\.tabs\s*>\s*\[role="tab"\]\s*\{([^}]*)\}/s)?.[1] ?? "";
  expect(segment).toContain("flex: 0 1 auto");
  expect(segment).toContain("min-width: 0");
  expect(segment).toContain("text-overflow: ellipsis");
  expect(segment).toContain("white-space: nowrap");
});

test("lixeira do componente não recebe limite de largura das linhas comuns", () => {
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  expect(css).toMatch(
    /\.setting-row\s*>\s*\.component-remove\s*\{[^}]*max-width:\s*none\s*;/s,
  );
});

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

// A body-level clip cuts the menu portal; a placeholder that matches the value
// makes an empty field look filled (reported twice in the Omarchy app).
test("Linux recorta só a raiz e o placeholder não imita valor digitado", () => {
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  const linux =
    css.match(/:root\[data-platform="linux"\]\s*\{([^}]*)\}/s)?.[1] ?? "";
  expect(linux).toContain("overflow: hidden");
  expect(linux).not.toMatch(/^\s*height\s*:/m);
  expect(css).not.toMatch(/:root\[data-platform="linux"\]\s+body\s*\{/s);
  const html = css.match(/^html\s*\{([^}]*)\}/ms)?.[1] ?? "";
  const body = css.match(/^body\s*\{([^}]*)\}/ms)?.[1] ?? "";
  expect(html).not.toMatch(/^\s*height\s*:/m);
  expect(html).not.toMatch(/^\s*overflow\s*:/m);
  expect(body).not.toMatch(/^\s*height\s*:/m);
  expect(body).not.toMatch(/^\s*overflow\s*:/m);

  const placeholder =
    css.match(
      /input::placeholder,\s*textarea::placeholder\s*\{([^}]*)\}/s,
    )?.[1] ?? "";
  expect(placeholder).toContain(
    "color: color-mix(in srgb, var(--text) 65%, var(--field))",
  );
  const omarchy = readFileSync(
    new URL("./omarchy.css", import.meta.url),
    "utf8",
  );
  expect(omarchy).not.toMatch(/::placeholder/);
});
