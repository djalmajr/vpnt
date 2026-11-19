/**
 * Temporary panel height for the open Options menu.
 *
 * Radix owns where the menu goes: above the trigger, end-aligned, flipped or
 * clamped when it does not fit. It can only fit the menu if the window is tall
 * enough *and* the trigger sits low enough, so this module only decides how tall
 * the native window should be and keeps the footer at its bottom edge while the
 * menu is open. It never computes a menu coordinate.
 *
 * The reservation exists only while a menu holds it: closing, navigating away
 * and unmounting all release it, and the natural height returns.
 */

import { isLinuxPlatform } from "./platform";

/** Marks `<html>` while a menu holds a reservation; styles.css stretches the
 * panel to the window and pins the footer to the bottom. */
export const RESERVE_ATTRIBUTE = "data-menu-reserve";

/** Window height at which the menu's intrinsic height fits above the trigger. */
export function menuNeed({
  menuScrollHeight,
  menuBorders,
  gap,
  collisionPadding,
  triggerToPanelBottom,
}: {
  /** `scrollHeight` of the menu: its full content, even when it is clipped. */
  menuScrollHeight: number;
  /** `offsetHeight - clientHeight`: borders (and a horizontal scrollbar). */
  menuBorders: number;
  /** Radix `sideOffset` between trigger and menu. */
  gap: number;
  /** Radix `collisionPadding` kept free at the top of the window. */
  collisionPadding: number;
  /** Distance from the trigger's top edge to the panel's bottom edge. */
  triggerToPanelBottom: number;
}): number {
  return Math.ceil(
    menuScrollHeight +
      menuBorders +
      gap +
      collisionPadding +
      triggerToPanelBottom,
  );
}

/**
 * Height to ask the host for: the content height, raised to the predefined
 * panel height and to the reservation. Other hosts stop at the panel limit;
 * Linux has no UI ceiling and the host clamps to the monitor. The host still
 * clamps to the screen.
 */
export function requestedHeight({
  natural,
  reserve,
  min = 0,
  max = Number.POSITIVE_INFINITY,
}: {
  natural: number;
  reserve: number;
  /** Predefined panel height; the window never asks for less. */
  min?: number;
  max?: number;
}): number {
  const limit =
    Number.isFinite(max) && max > 0 ? max : Number.POSITIVE_INFINITY;
  return Math.ceil(
    Math.min(limit, Math.max(natural, reserve, min > 0 ? min : 0)),
  );
}

/** Reservations by owner; the largest one wins and `0` means none. */
export function createReserve() {
  const holders = new Map<symbol, number>();
  const listeners = new Set<() => void>();
  const value = () => Math.max(0, ...holders.values());
  const notify = () => {
    for (const listener of [...listeners]) listener();
  };
  return {
    value,
    /** Idempotent: an unchanged reservation does not notify. */
    hold(owner: symbol, height: number) {
      if (!(height > 0) || holders.get(owner) === height) return;
      holders.set(owner, height);
      notify();
    },
    release(owner: symbol) {
      if (holders.delete(owner)) notify();
    },
    subscribe(listener: () => void) {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
  };
}

export const menuReserve = createReserve();

/**
 * Reports intrinsic content plus the fixed panel structure, raised to the active
 * reservation. The viewport may clip the rendered panel, but must not cap this
 * request: the host decides how much physical screen space is available.
 */
export function observePanelHeight(
  send: (height: number) => void,
  reserve = menuReserve,
): () => void {
  const root = document.documentElement;
  let previous = 0;
  const report = () => {
    // A window that was never shown can have an empty viewport (WebKitGTK on
    // Linux). The text then wraps in a zero-width column and the panel would ask
    // for its limit, so the window would open at it. Measure once the window
    // has a size: the panel resizes then and the observer reports again.
    if (!(window.innerWidth > 0 && window.innerHeight > 0)) return;
    const panel = document.getElementById("panel");
    const content = panel?.querySelector<HTMLElement>(".panel-content");
    const panelHeight = panel?.getBoundingClientRect().height ?? 360;
    // Replace the clipped scroll box with its full content. The remaining panel
    // height includes padding, gap and footer; preserve scroll box borders too.
    const natural = content
      ? panelHeight -
        content.getBoundingClientRect().height +
        content.scrollHeight +
        (content.offsetHeight - content.clientHeight)
      : panelHeight;
    // max-height now combines viewport and token with min(); parse the token
    // directly, since parseFloat on the computed min() expression is NaN.
    // Linux marks <html> before the UI loads and overrides the token with 100vh:
    // there is no 720 px ceiling to cap the request, only the host's available
    // monitor height. Other hosts keep the token ceiling.
    const max =
      panel && !isLinuxPlatform()
        ? Number.parseFloat(
            getComputedStyle(panel).getPropertyValue("--panel-max-height"),
          )
        : Number.POSITIVE_INFINITY;
    // The token, not the computed `min-height`: that one follows the current
    // window (`100vh`) and would keep a small window small.
    const min = Number.parseFloat(
      getComputedStyle(root).getPropertyValue("--panel-min-height"),
    );
    const height = requestedHeight({
      natural,
      reserve: reserve.value(),
      min: Number.isFinite(min) ? min : 0,
      max,
    });
    if (height !== previous) {
      previous = height;
      send(height);
    }
  };
  const observer = new ResizeObserver(report);
  const target = document.getElementById("root");
  const observed = new Set<Element>();
  const observeContent = () => {
    const panel = document.getElementById("panel");
    const content = panel?.querySelector(".panel-content");
    const targets = new Set<Element>([
      ...(target ? [target] : []),
      ...(panel ? [panel, ...panel.children] : []),
      ...(content ? [content, ...content.children] : []),
    ]);
    for (const element of observed) {
      if (!targets.has(element)) {
        observer.unobserve(element);
        observed.delete(element);
      }
    }
    for (const element of targets) {
      if (!observed.has(element)) {
        observer.observe(element);
        observed.add(element);
      }
    }
  };
  // A fixed outer box does not resize when its scrollHeight grows. Observe its
  // children, and refresh the observed set on route/content changes as well.
  const mutations = new MutationObserver(() => {
    observeContent();
    report();
  });
  if (target)
    mutations.observe(target, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
    });
  observeContent();
  const mark = () => {
    root.toggleAttribute(RESERVE_ATTRIBUTE, reserve.value() > 0);
    report();
  };
  const unsubscribe = reserve.subscribe(mark);
  mark();
  return () => {
    unsubscribe();
    mutations.disconnect();
    observer.disconnect();
    root.removeAttribute(RESERVE_ATTRIBUTE);
  };
}
