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
 * Height to ask the host for: the content height, raised to the reservation,
 * never above the panel limit. The host still clamps to the screen.
 */
export function requestedHeight({
  natural,
  reserve,
  max = Number.POSITIVE_INFINITY,
}: {
  natural: number;
  reserve: number;
  max?: number;
}): number {
  const limit =
    Number.isFinite(max) && max > 0 ? max : Number.POSITIVE_INFINITY;
  return Math.ceil(Math.min(limit, Math.max(natural, reserve)));
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
 * Reports the height the host window should have: the panel's own height, raised
 * to the active reservation. Without a reservation this is exactly the previous
 * behavior. Returns a cleanup that stops observing and removes the marker.
 */
export function observePanelHeight(
  send: (height: number) => void,
  reserve = menuReserve,
): () => void {
  const root = document.documentElement;
  let previous = 0;
  const report = () => {
    const panel = document.getElementById("panel");
    const natural = panel?.getBoundingClientRect().height ?? 360;
    const max = panel
      ? Number.parseFloat(getComputedStyle(panel).maxHeight)
      : 0;
    const height = requestedHeight({
      natural,
      reserve: reserve.value(),
      max,
    });
    if (height !== previous) {
      previous = height;
      send(height);
    }
  };
  const observer = new ResizeObserver(report);
  const target = document.getElementById("root");
  if (target) observer.observe(target);
  const mark = () => {
    root.toggleAttribute(RESERVE_ATTRIBUTE, reserve.value() > 0);
    report();
  };
  const unsubscribe = reserve.subscribe(mark);
  mark();
  return () => {
    unsubscribe();
    observer.disconnect();
    root.removeAttribute(RESERVE_ATTRIBUTE);
  };
}
