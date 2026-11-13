import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import type { ReactNode } from "react";
import { Icon, type IconName } from "./common";

/**
 * Shared footer menu, built on the same Radix dropdown primitive the
 * ai-usagebar reference uses (`@radix-ui/react-dropdown-menu` 2.1.24).
 *
 * The primitive owns everything positional and behavioral: it anchors the
 * content to the live trigger (above it, end-aligned, 6 px gap), repositions on
 * resize and scroll, flips and clamps on short viewports, and handles Escape,
 * outside dismissal, keyboard navigation, disabled items, focus return and
 * cleanup. Nothing here measures the DOM, keeps screen coordinates or adds a
 * document-level listener, and there is no hand-built ARIA menu.
 */
export function Menu({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <DropdownMenu.Root modal={false}>
      <DropdownMenu.Trigger asChild>
        <button type="button" className="options-trigger">
          {label}
          <Icon name="down" />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          className="options-menu"
          align="end"
          side="top"
          sideOffset={6}
          collisionPadding={8}
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
