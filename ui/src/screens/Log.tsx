import { useId, useState } from "react";
import { Header, Icon, type T } from "../components/common";
import type { Snapshot } from "../model";
import type { Navigate, Run } from "../navigation";

export function Log({
  snapshot,
  id,
  navigate,
  run,
  t,
  locale,
}: {
  snapshot: Snapshot;
  id?: string;
  navigate: Navigate;
  run: Run;
  t: T;
  locale: string;
}) {
  const [selected, setSelected] = useState(id ?? snapshot.vpns[0]?.profile.id);
  const [copied, setCopied] = useState(false);
  const panelId = useId();
  const vpn =
    snapshot.vpns.find((vpn) => vpn.profile.id === selected) ??
    snapshot.vpns[0];
  const selectedId = vpn?.profile.id;
  const tabId = (id: string) => `${panelId}-${id}`;
  const lines =
    vpn?.log.map(
      (line) =>
        `${new Date(line.timestamp * 1000).toLocaleTimeString(locale)} ${t(`state.${line.state}`)}`,
    ) ?? [];
  return (
    <>
      <Header
        title={t("log")}
        back={() => navigate({ page: "panel" })}
        action={
          <button
            type="button"
            className="icon-button"
            aria-label={t("refresh")}
            onClick={() => void run({ type: "get_snapshot" })}
          >
            <Icon name="refresh" />
          </button>
        }
        t={t}
      />
      <div className="tabs" role="tablist" aria-label={t("vpns")}>
        {snapshot.vpns.map((vpn) => (
          <button
            type="button"
            key={vpn.profile.id}
            role="tab"
            id={tabId(vpn.profile.id)}
            aria-controls={panelId}
            aria-selected={vpn.profile.id === selectedId}
            tabIndex={vpn.profile.id === selectedId ? 0 : -1}
            className={vpn.profile.id === selectedId ? "primary" : ""}
            onKeyDown={(event) => {
              const tabs = Array.from(
                event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>(
                  "[role=tab]",
                ) ?? [],
              );
              const index = tabs.indexOf(event.currentTarget);
              const next =
                event.key === "ArrowRight"
                  ? (index + 1) % tabs.length
                  : event.key === "ArrowLeft"
                    ? (index - 1 + tabs.length) % tabs.length
                    : event.key === "Home"
                      ? 0
                      : event.key === "End"
                        ? tabs.length - 1
                        : -1;
              if (next < 0) return;
              event.preventDefault();
              tabs[next]?.focus();
              tabs[next]?.click();
            }}
            onClick={() => {
              setSelected(vpn.profile.id);
              setCopied(false);
            }}
          >
            {vpn.profile.name}
          </button>
        ))}
      </div>
      <div
        id={panelId}
        role="tabpanel"
        aria-labelledby={vpn ? tabId(vpn.profile.id) : undefined}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: Static log panels need keyboard focus for scrolling (ARIA APG tabs pattern).
        tabIndex={0}
      >
        {lines.length ? (
          <pre className="log-lines">{lines.join("\n")}</pre>
        ) : (
          <div className="empty">
            <Icon name="shield" large />
            <strong>{t("noLog")}</strong>
            <p>{t("noLogHint")}</p>
          </div>
        )}
      </div>
      {!!lines.length && (
        <div className="spread">
          <small>{t("lastLines")}</small>
          <button
            type="button"
            onClick={() => {
              void navigator.clipboard
                .writeText(lines.join("\n"))
                .then(() => setCopied(true))
                .catch(() => setCopied(false));
            }}
          >
            {t(copied ? "copied" : "copy")}
          </button>
        </div>
      )}
    </>
  );
}
