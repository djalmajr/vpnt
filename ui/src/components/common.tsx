import { type ReactNode, useLayoutEffect, useRef } from "react";
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
};
export function Icon({
  name,
  large = false,
}: {
  name: keyof typeof paths;
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
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-label={label}
      aria-checked={checked}
      className={`switch ${checked ? "on" : ""}`}
      onClick={() => onChange(!checked)}
    >
      <span />
    </button>
  );
}
export function Row({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children?: ReactNode;
}) {
  return (
    <div className="setting-row">
      <span>
        {label}
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
