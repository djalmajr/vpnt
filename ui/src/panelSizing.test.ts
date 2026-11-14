import { expect, test } from "bun:test";
import { createReserve, menuNeed, requestedHeight } from "./panelSizing";

// Mutation captured: sizing only the viewport and leaving the trigger where it
// was keeps the menu clipped. The need must include the distance below the
// trigger, the Radix gap and the top collision padding, and must count content
// that is currently clipped (scrollHeight), not the clipped box.
test("a reserva soma conteúdo intrínseco, bordas, folga e distância do gatilho", () => {
  expect(
    menuNeed({
      menuScrollHeight: 228,
      menuBorders: 0,
      gap: 6,
      collisionPadding: 8,
      triggerToPanelBottom: 32,
    }),
  ).toBe(274);
  expect(
    menuNeed({
      menuScrollHeight: 227.2,
      menuBorders: 2,
      gap: 6,
      collisionPadding: 8,
      triggerToPanelBottom: 32,
    }),
  ).toBe(276);
});

// Mutation captured: a permanent large height. Without a reservation the
// request is exactly the natural height; a reservation raises it and never
// lowers it, and it stops at the panel limit.
test("altura pedida: natural sem reserva, elevada com reserva, limitada ao máximo", () => {
  expect(requestedHeight({ natural: 183.4, reserve: 0 })).toBe(184);
  expect(requestedHeight({ natural: 183, reserve: 274 })).toBe(274);
  expect(requestedHeight({ natural: 500, reserve: 274 })).toBe(500);
  expect(requestedHeight({ natural: 183, reserve: 900, max: 720 })).toBe(720);
  expect(requestedHeight({ natural: 183, reserve: 274, max: Number.NaN })).toBe(
    274,
  );
});

// Mutation captured: a release that does not restore the natural height, a
// notification loop on an unchanged measure, or a stale owner clearing another.
test("reserva: libera ao fechar, é idempotente e separa os donos", () => {
  const reserve = createReserve();
  const calls: number[] = [];
  const stop = reserve.subscribe(() => calls.push(reserve.value()));
  const a = Symbol("a");
  const b = Symbol("b");
  reserve.hold(a, 274);
  reserve.hold(a, 274);
  expect(calls).toEqual([274]);
  reserve.hold(b, 300);
  reserve.release(a);
  expect(reserve.value()).toBe(300);
  reserve.release(a);
  reserve.release(b);
  expect(reserve.value()).toBe(0);
  expect(calls).toEqual([274, 300, 300, 0]);
  reserve.hold(a, 0);
  reserve.hold(a, Number.NaN);
  expect(reserve.value()).toBe(0);
  stop();
  reserve.hold(a, 100);
  expect(calls).toHaveLength(4);
});
