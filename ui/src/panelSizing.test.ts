import { expect, test } from "bun:test";
import {
  createReserve,
  menuNeed,
  observePanelHeight,
  requestedHeight,
} from "./panelSizing";

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

test("a altura predefinida é o piso do pedido e respeita o teto", () => {
  expect(requestedHeight({ natural: 300, reserve: 0, min: 480 })).toBe(480);
  expect(requestedHeight({ natural: 700, reserve: 0, min: 480 })).toBe(700);
  expect(
    requestedHeight({ natural: 300, reserve: 0, min: 480, max: 400 }),
  ).toBe(400);
  expect(requestedHeight({ natural: 300, reserve: 0 })).toBe(300);
  // A reserva do menu soma-se ao piso só quando o ultrapassa.
  expect(requestedHeight({ natural: 300, reserve: 400, min: 480 })).toBe(480);
  expect(requestedHeight({ natural: 300, reserve: 600, min: 480 })).toBe(600);
});

test("conteúdo limitado pelo viewport cresce até o teto e é observado por dentro", () => {
  const keys = [
    "document",
    "getComputedStyle",
    "ResizeObserver",
    "MutationObserver",
  ] as const;
  const originals = keys.map((key) =>
    Object.getOwnPropertyDescriptor(globalThis, key),
  );
  let contentHeight = 600;
  const child = {};
  const content = {
    get scrollHeight() {
      return contentHeight;
    },
    offsetHeight: 432,
    clientHeight: 432,
    getBoundingClientRect: () => ({ height: 432 }),
    children: [child],
  };
  const panel = {
    getBoundingClientRect: () => ({ height: 480 }),
    querySelector: () => content,
    children: [content],
  };
  const root = { toggleAttribute() {}, removeAttribute() {} };
  const target = {};
  const observed = new Set<unknown>();
  let resize = () => {};
  let mutate = () => {};
  let disconnected = 0;
  const mocks = [
    {
      documentElement: root,
      getElementById: (id: string) => (id === "panel" ? panel : target),
    },
    () => ({
      getPropertyValue: (key: string) =>
        key === "--panel-max-height" ? "720px" : "480px",
    }),
    class {
      constructor(callback: () => void) {
        resize = callback;
      }
      observe(element: unknown) {
        observed.add(element);
      }
      unobserve(element: unknown) {
        observed.delete(element);
      }
      disconnect() {
        observed.clear();
      }
    },
    class {
      constructor(callback: () => void) {
        mutate = callback;
      }
      observe() {}
      disconnect() {
        disconnected++;
      }
    },
  ];
  try {
    keys.forEach((key, index) => {
      Object.defineProperty(globalThis, key, {
        configurable: true,
        value: mocks[index],
      });
    });
    const requests: number[] = [];
    const reserve = createReserve();
    const stop = observePanelHeight((height) => requests.push(height), reserve);
    expect(requests).toEqual([648]);
    expect(observed.has(content)).toBe(true);
    expect(observed.has(child)).toBe(true);
    contentHeight = 650;
    resize();
    expect(requests).toEqual([648, 698]);
    contentHeight = 900;
    resize();
    expect(requests.at(-1)).toBe(720);
    expect(content.scrollHeight).toBeGreaterThan(content.clientHeight);
    resize();
    expect(requests).toEqual([648, 698, 720]);
    const added = {};
    content.children.push(added);
    contentHeight = 432;
    mutate();
    expect(observed.has(added)).toBe(true);
    expect(requests.at(-1)).toBe(480);
    content.children.pop();
    mutate();
    expect(observed.has(added)).toBe(false);
    const owner = Symbol();
    reserve.hold(owner, 700);
    expect(requests.at(-1)).toBe(700);
    reserve.release(owner);
    expect(requests.at(-1)).toBe(480);
    stop();
    expect(observed.size).toBe(0);
    expect(disconnected).toBe(1);
  } finally {
    keys.forEach((key, index) => {
      const original = originals[index];
      if (original) Object.defineProperty(globalThis, key, original);
      else Reflect.deleteProperty(globalThis, key);
    });
  }
});
