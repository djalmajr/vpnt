import { useCallback, useEffect, useRef } from "react";
import { active, type Snapshot } from "../model";
import type { Navigate, Run } from "../navigation";
import { Icon, type T } from "./common";

export function Footer({
  snapshot,
  navigate,
  run,
  t,
}: {
  snapshot: Snapshot;
  navigate: Navigate;
  run: Run;
  t: T;
}) {
  const ref = useRef<HTMLDetailsElement>(null);
  const anyActive = snapshot.vpns.some((vpn) => active(vpn.state));
  const close = useCallback(() => {
    if (ref.current) ref.current.open = false;
  }, []);
  useEffect(() => {
    const outside = (event: MouseEvent) => {
      if (event.target instanceof Node && !ref.current?.contains(event.target))
        close();
    };
    document.addEventListener("mousedown", outside);
    return () => document.removeEventListener("mousedown", outside);
  }, [close]);
  return (
    <footer className="footer">
      <small>{t("version", { version: snapshot.version })}</small>
      <details className="options" ref={ref}>
        <summary>
          {t("options")} <Icon name="down" />
        </summary>
        <nav aria-label={t("options")}>
          <button
            className="menu-item"
            type="button"
            disabled={!anyActive}
            onClick={() => {
              close();
              void run({ type: "disconnect_all" });
            }}
          >
            {t("disconnectAll")}
          </button>
          <button
            className="menu-item"
            type="button"
            disabled={!anyActive}
            onClick={() => {
              close();
              for (const vpn of snapshot.vpns.filter((vpn) =>
                active(vpn.state),
              ))
                void run({ type: "probe", id: vpn.profile.id });
            }}
          >
            {t("testNow")}
          </button>
          <button
            className="menu-item"
            type="button"
            onClick={() => {
              close();
              navigate({ page: "log" });
            }}
          >
            {t("viewLog")}
          </button>
          <hr />
          <button
            className="menu-item"
            type="button"
            onClick={() => {
              close();
              navigate({ page: "preferences" });
            }}
          >
            {t("preferences")}
          </button>
          <button
            className="menu-item"
            type="button"
            onClick={() => {
              close();
              navigate({ page: "about" });
            }}
          >
            {t("about")}
          </button>
          <hr />
          <button
            className="menu-item"
            type="button"
            onClick={() => {
              close();
              void run({ type: "quit" });
            }}
          >
            {t("quit")}
          </button>
        </nav>
      </details>
    </footer>
  );
}
