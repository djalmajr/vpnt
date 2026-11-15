import {
  type ReactNode,
  type SelectHTMLAttributes,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { helpPosition } from "../helpPosition";
import type { MessageKey } from "../i18n";

export type T = (
  key: MessageKey,
  values?: Record<string, string | number>,
) => string;
const paths = {
  shield:
    "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z",
  settings:
    "M21 4h-7 M10 4H3 M21 12h-9 M8 12H3 M21 20h-5 M12 20H3 M14 2v4 M8 10v4 M16 18v4",
  back: "M15 18l-6-6 6-6",
  chevron: "M9 18l6-6-6-6",
  down: "M6 9l6 6 6-6",
  plus: "M12 5v14 M5 12h14",
  loader: "M21 12a9 9 0 1 1-6.219-8.56",
  refresh:
    "M3 12a9 9 0 0 1 15-6.7L21 8 M21 3v5h-5 M21 12a9 9 0 0 1-15 6.7L3 16 M3 21v-5h5",
  log: "M4 17l6-5-6-5 M12 19h8",
  help: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z M9.5 9a2.5 2.5 0 1 1 4.3 1.7C12.6 11.5 12 12 12 13.5 M12 17v.01",
  info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z M12 11v5 M12 7.5v.01",
  power: "M12 3v9 M18.36 6.64a9 9 0 1 1-12.73 0",
  quit: "M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4 M10 17l5-5-5-5 M15 12H3",
};
export type IconName = keyof typeof paths;
export function Icon({
  name,
  large = false,
}: {
  name: IconName;
  large?: boolean;
}) {
  return (
    <svg
      aria-hidden="true"
      className={`icon ${large ? "large" : ""} ${name === "loader" ? "spin" : ""}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={paths[name]} />
    </svg>
  );
}
/**
 * Escape while a hint is open closes only the hint. Registered in the capture
 * phase on the window, so it runs before the document listener that hides the
 * native popover on Escape, and stops the event from reaching it.
 */
export function helpEscape(close: () => void) {
  return (
    event: Pick<
      KeyboardEvent,
      "key" | "preventDefault" | "stopImmediatePropagation"
    >,
  ) => {
    if (event.key !== "Escape") return;
    event.preventDefault();
    event.stopImmediatePropagation();
    close();
  };
}
export function Help({ text }: { text: string }) {
  const id = useId();
  const trigger = useRef<HTMLSpanElement>(null);
  const content = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ left: 0, top: 0 });
  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const anchor = trigger.current;
      const tip = content.current;
      if (!anchor || !tip) return;
      const padding = Number.parseFloat(
        getComputedStyle(tip).getPropertyValue("--space-md"),
      );
      setPosition(
        helpPosition(
          anchor.getBoundingClientRect(),
          tip.getBoundingClientRect(),
          { width: window.innerWidth, height: window.innerHeight },
          padding,
        ),
      );
    };
    const onEscape = helpEscape(() => setOpen(false));
    place();
    const observer = new ResizeObserver(place);
    if (trigger.current) observer.observe(trigger.current);
    if (content.current) observer.observe(content.current);
    window.addEventListener("resize", place);
    document.addEventListener("scroll", place, true);
    window.addEventListener("keydown", onEscape, true);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", place);
      document.removeEventListener("scroll", place, true);
      window.removeEventListener("keydown", onEscape, true);
    };
  }, [open]);
  const leave = (target: EventTarget | null, keepFocus = false) => {
    if (keepFocus && document.activeElement === trigger.current) return;
    if (
      target instanceof Node &&
      (trigger.current?.contains(target) || content.current?.contains(target))
    )
      return;
    setOpen(false);
  };
  return (
    <>
      <span
        ref={trigger}
        className="help-trigger"
        role="img"
        // biome-ignore lint/a11y/noNoninteractiveTabindex: The reference help icon must reveal its tooltip to keyboard users.
        tabIndex={0}
        aria-label={text}
        aria-describedby={open ? id : undefined}
        onPointerEnter={() => setOpen(true)}
        onPointerLeave={(event) => leave(event.relatedTarget, true)}
        onFocus={() => setOpen(true)}
        onBlur={(event) => leave(event.relatedTarget)}
      >
        <Icon name="help" />
      </span>
      {open &&
        createPortal(
          <span
            ref={content}
            id={id}
            role="tooltip"
            className="help-tooltip"
            style={position}
            onPointerLeave={(event) => leave(event.relatedTarget, true)}
          >
            {text}
          </span>,
          document.body,
        )}
    </>
  );
}
/* A real native <select>: the platform popup and keyboard semantics stay with
   the element, the wrapper only hosts the shared chevron. `busy` blocks the
   control like `disabled` but keeps the idle paint: a transient wait must not
   look permanently unavailable. The `busy` class is only for that state, so a
   permanent `disabled` keeps its dim/secondary appearance. */
export function Select({
  children,
  busy = false,
  disabled = false,
  "aria-busy": ariaBusy,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & { busy?: boolean }) {
  return (
    <span
      className={busy && !disabled ? "select-control busy" : "select-control"}
    >
      <select
        {...props}
        aria-busy={busy ? true : ariaBusy}
        disabled={disabled || busy}
      >
        {children}
      </select>
      <Icon name="down" />
    </span>
  );
}
export function Header({
  title,
  back,
  backDisabled = false,
  action,
  t,
}: {
  title: string;
  back?: () => void;
  backDisabled?: boolean;
  action?: ReactNode;
  t: T;
}) {
  return (
    <header className={`header ${back ? "with-back" : ""}`}>
      {back && (
        <button
          type="button"
          className="icon-button"
          onClick={back}
          disabled={backDisabled}
          aria-label={t("back")}
        >
          <Icon name="back" />
        </button>
      )}
      <h1>{title}</h1>
      {action ?? (back ? <span className="icon-placeholder" /> : null)}
    </header>
  );
}
export function Toggle({
  label,
  checked,
  disabled = false,
  busy = false,
  onChange,
}: {
  label: string;
  checked: boolean;
  disabled?: boolean;
  busy?: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-label={label}
      aria-checked={checked}
      aria-busy={busy ? true : undefined}
      disabled={disabled || busy}
      className={`switch ${checked ? "on" : ""} ${disabled ? "dim" : ""} ${busy && !disabled ? "busy" : ""}`}
      onClick={() => onChange(!checked)}
    >
      <span />
    </button>
  );
}
export function Row({
  label,
  hint,
  help,
  children,
}: {
  label: string;
  hint?: string;
  help?: string;
  children?: ReactNode;
}) {
  return (
    <div className="setting-row">
      <span>
        <span className="setting-label">
          {label}
          {help && <Help text={help} />}
        </span>
        {hint && <small>{hint}</small>}
      </span>
      {children}
    </div>
  );
}
export function Group({ children }: { children: ReactNode }) {
  return <section className="group">{children}</section>;
}
export function Notice({
  tone = "info",
  children,
}: {
  tone?: "info" | "warn" | "error";
  children: ReactNode;
}) {
  return <div className={`notice ${tone}`}>{children}</div>;
}
export function Dialog({
  title,
  children,
  close,
  busy = false,
  t,
}: {
  title: string;
  children: ReactNode;
  close: () => void;
  busy?: boolean;
  t: T;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useLayoutEffect(() => {
    const dialog = ref.current;
    const previous = document.activeElement;
    dialog?.showModal();
    return () => {
      dialog?.close();
      if (previous instanceof HTMLElement && previous.isConnected)
        previous.focus({ preventScroll: true });
    };
  }, []);
  useLayoutEffect(() => {
    if (busy) ref.current?.focus({ preventScroll: true });
  }, [busy]);
  return (
    <dialog
      ref={ref}
      tabIndex={-1}
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) close();
      }}
      aria-label={title}
      aria-busy={busy}
    >
      <h2>{title}</h2>
      {children}
      <button type="button" className="sr-only" onClick={close} disabled={busy}>
        {t("close")}
      </button>
    </dialog>
  );
}
