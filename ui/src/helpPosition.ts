type Rect = { left: number; top: number; bottom: number; width: number };
type Size = { width: number; height: number };

/** The tooltip's CSS bounds its size to the viewport minus two paddings. */
export function helpPosition(
  anchor: Rect,
  tip: Size,
  viewport: Size,
  padding: number,
) {
  const above = anchor.top - tip.height;
  const top =
    above >= padding || anchor.top > viewport.height - anchor.bottom
      ? above
      : anchor.bottom;
  return {
    left: Math.max(
      padding,
      Math.min(
        anchor.left + (anchor.width - tip.width) / 2,
        viewport.width - tip.width - padding,
      ),
    ),
    top: Math.max(
      padding,
      Math.min(top, viewport.height - tip.height - padding),
    ),
  };
}
