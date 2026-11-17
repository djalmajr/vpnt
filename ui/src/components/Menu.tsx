import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { type ReactNode, useLayoutEffect, useRef, useState } from "react";
import { menuNeed, menuReserve } from "../panelSizing";
import { Icon, type IconName } from "./common";

/** Radix placement inputs, shared with the sizing so both agree. */
const SIDE_OFFSET = 6;
const COLLISION_PADDING = 8;

/**
 * Shared footer menu, built on the same Radix dropdown primitive the
 * ai-usagebar reference uses (`@radix-ui/react-dropdown-menu` 2.1.24).
 *
 * The primitive owns everything positional and behavioral: it anchors the
 * content to the live trigger (above it, end-aligned, 6 px gap), repositions on
 * resize and scroll, flips and clamps on short viewports, and handles Escape,
 * outside dismissal, keyboard navigation, disabled items, focus return and
 * cleanup. There is no hand-built ARIA menu and no menu coordinate here.
 *
 * The one thing the primitive cannot do is make room: a short panel leaves no
 * space above the trigger, so the menu would be clipped and scroll although the
 * screen has room. While the menu is open it therefore reserves the window
 * height that fits its intrinsic content (`panelSizing`); Radix then places it
 * as usual. Closing, navigating away and unmounting release the reservation.
 */
export function Menu({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [content, setContent] = useState<HTMLDivElement | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  useLayoutEffect(() => {
    const anchor = trigger.current;
    const panel = anchor?.closest<HTMLElement>("#panel");
    if (!open || !content || !anchor || !panel) return;
    const owner = Symbol("menu");
    // The intrinsic height, not the current one: `scrollHeight` keeps counting
    // content the available height is clipping, so the measure is the same
    // whether the menu is cramped or roomy and cannot feed back into itself.
    const measure = () =>
      menuReserve.hold(
        owner,
        menuNeed({
          menuScrollHeight: content.scrollHeight,
          menuBorders: content.offsetHeight - content.clientHeight,
          gap: SIDE_OFFSET,
          collisionPadding: COLLISION_PADDING,
          triggerToPanelBottom:
            panel.getBoundingClientRect().bottom -
            anchor.getBoundingClientRect().top,
        }),
      );
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(content);
    for (const child of content.children) observer.observe(child);
    return () => {
      observer.disconnect();
      menuReserve.release(owner);
    };
  }, [open, content]);
  return (
    <DropdownMenu.Root modal={false} open={open} onOpenChange={setOpen}>
      <DropdownMenu.Trigger asChild>
        <button ref={trigger} type="button" className="options-trigger">
          {label}
          <Icon name="down" />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          ref={setContent}
          className="options-menu"
          align="end"
          side="top"
          sideOffset={SIDE_OFFSET}
          collisionPadding={COLLISION_PADDING}
        >
          {children}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

export function MenuItem({
  icon,
  disabled = false,
  onSelect,
  children,
}: {
  icon: IconName;
  disabled?: boolean;
  onSelect: () => void;
  children: ReactNode;
}) {
  return (
    <DropdownMenu.Item
      className="menu-item"
      disabled={disabled}
      onSelect={onSelect}
    >
      <Icon name={icon} />
      <span className="menu-item-label">{children}</span>
    </DropdownMenu.Item>
  );
}

export function MenuSeparator() {
  return <DropdownMenu.Separator className="menu-separator" />;
}
