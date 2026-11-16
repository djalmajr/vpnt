import { expect, test } from "bun:test";
import { helpPosition } from "./helpPosition";

// Regression: a centered tooltip near a panel edge must stay fully in view.
test("a dica colide com as duas laterais do popover de 320 px", () => {
  const tip = { width: 200, height: 144 };
  const viewport = { width: 320, height: 480 };
  expect(
    helpPosition(
      { left: 0, top: 200, bottom: 212, width: 12 },
      tip,
      viewport,
      12,
    ),
  ).toEqual({ left: 12, top: 56 });
  expect(
    helpPosition(
      { left: 308, top: 200, bottom: 212, width: 12 },
      tip,
      viewport,
      12,
    ),
  ).toEqual({ left: 108, top: 56 });
});

test("a dica inverte perto do topo e conserva a margem inferior", () => {
  const tip = { width: 200, height: 144 };
  const viewport = { width: 320, height: 480 };
  expect(
    helpPosition(
      { left: 154, top: 8, bottom: 20, width: 12 },
      tip,
      viewport,
      12,
    ),
  ).toEqual({ left: 60, top: 20 });
  expect(
    helpPosition(
      { left: 154, top: 460, bottom: 472, width: 12 },
      tip,
      viewport,
      12,
    ),
  ).toEqual({ left: 60, top: 316 });
});

test("com dica alta e viewport estreito, ambas as bordas continuam dentro", () => {
  for (const width of [280, 320, 640]) {
    for (const height of [180, 480, 720]) {
      const tip = { width: Math.min(200, width - 24), height: height - 24 };
      for (const left of [0, width / 2, width - 12]) {
        for (const top of [0, height / 2, height - 12]) {
          const position = helpPosition(
            { left, top, bottom: top + 12, width: 12 },
            tip,
            { width, height },
            12,
          );
          expect(position.left).toBeGreaterThanOrEqual(12);
          expect(position.top).toBeGreaterThanOrEqual(12);
          expect(position.left + tip.width).toBeLessThanOrEqual(width - 12);
          expect(position.top + tip.height).toBeLessThanOrEqual(height - 12);
        }
      }
    }
  }
});
