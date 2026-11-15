import { active, type VpnView } from "../model";
import type { Navigate, Run } from "../navigation";
import { Icon, Notice, type T } from "./common";

export function VpnCard({
  vpn,
  t,
  run,
  navigate,
  secrets,
}: {
  vpn: VpnView;
  t: T;
  run: Run;
  navigate: Navigate;
  secrets: () => void;
}) {
  const { state, profile, cleaning } = vpn;
  const cleanupId = `cleanup-${profile.id}`;
  // While cleaning, the Notice action stays focusable (aria-disabled, inert
  // click) so the keyboard reaches it and hears why it is unavailable.
  const pending = cleaning
    ? { "aria-disabled": true as const, "aria-describedby": cleanupId }
    : {};
  const busy = [
    "connecting",
    "reconnecting",
    "disconnecting",
    "verifying",
  ].includes(state);
  const disabled =
    cleaning ||
    ["offline", "helper_missing", "missing_program", "disconnecting"].includes(
      state,
    );
  const cancelable = state === "connecting" || state === "reconnecting";
  const missingSecret = state === "missing_secret";
  const on = active(state);
  const warning = [
    "unresponsive",
    "dropped",
    "missing_secret",
    "missing_program",
  ].includes(state);
  const danger = ["credentials_rejected", "gateway_timeout"].includes(state);
  const color = danger
    ? "danger-text"
    : warning
      ? "warning-text"
      : state === "connected" || state === "verifying"
        ? "success-text"
        : state === "connecting" || state === "reconnecting"
          ? "primary-text"
          : "muted";
  const hint =
    state === "unresponsive"
      ? "staleHint"
      : state === "dropped"
        ? "droppedHint"
        : state === "credentials_rejected"
          ? "credentialsHint"
          : state === "gateway_timeout"
            ? "timeoutHint"
            : state === "missing_program"
              ? "programHint"
              : null;
  const toggle = () => {
    if (disabled || cancelable) return;
    if (missingSecret) {
      secrets();
      return;
    }
    // Preserve the direction shown by this snapshot, even if the host has
    // already changed state by the time it receives the command.
    void run({ type: on ? "disconnect" : "connect", id: profile.id });
  };
  return (
    // biome-ignore lint/a11y/useKeyWithClickEvents: The Details button owns keyboard navigation; the card is not a second tab stop.
    <article
      className="vpn-card"
      data-testid={`vpn-card-${profile.id}`}
      onClick={(event) => {
        if ((event.target as Element).closest("button, .notice")) return;
        navigate({ page: "profile", id: profile.id });
      }}
    >
      <div className="card-body">
        <span className="card-heading">
          <span className="identity">
            <strong>{profile.name}</strong>
            <small>
              {t(profile.kind)} ·{" "}
              {profile.networks.join(", ") || t("fullTunnel")}
            </small>
          </span>
          <span className="card-controls">
            <button
              type="button"
              onClick={toggle}
              disabled={!!disabled || cancelable}
              aria-label={`${profile.name}: ${t(`state.${state}`)}`}
              aria-pressed={on}
              className={`switch ${on ? "on" : ""} ${busy || disabled ? "dim" : ""}`}
            >
              <span />
            </button>
            <button
              type="button"
              className="icon-button"
              aria-label={t("profileDetails", { name: profile.name })}
              title={t("profileDetails", { name: profile.name })}
              onClick={() => navigate({ page: "profile", id: profile.id })}
            >
              <Icon name="chevron" />
            </button>
          </span>
        </span>
        <span className="card-state">
          <span className="status-line">
            <span className={color}>
              {busy ? <Icon name="loader" /> : <span className="dot" />}
            </span>
            <span>{t(`state.${state}`)}</span>
          </span>
          {cancelable && (
            <button
              type="button"
              className="card-cancel"
              onClick={() => void run({ type: "disconnect", id: profile.id })}
              aria-label={t("cancel")}
            >
              {t("cancel")}
            </button>
          )}
        </span>
      </div>
      {hint && (
        <Notice tone={danger ? "error" : "warn"}>
          <p>{t(hint)}</p>
          {cleaning && (
            <p id={cleanupId} role="status">
              {t("cleanupHint")}
            </p>
          )}
          <div className="actions">
            {state === "missing_program" ? (
              <button
                type="button"
                {...pending}
                onClick={() => {
                  if (!cleaning) void run({ type: "probe", id: profile.id });
                }}
              >
                {t("refresh")}
              </button>
            ) : (
              <>
                <button
                  type="button"
                  className="primary"
                  {...pending}
                  onClick={() => {
                    if (!cleaning)
                      void run({ type: "reconnect", id: profile.id });
                  }}
                >
                  {t(
                    state === "credentials_rejected" ||
                      state === "gateway_timeout"
                      ? "tryAgain"
                      : "reconnect",
                  )}
                </button>
                {state === "unresponsive" ? (
                  <button
                    type="button"
                    onClick={() =>
                      void run({ type: "disconnect", id: profile.id })
                    }
                  >
                    {t("disconnect")}
                  </button>
                ) : state === "credentials_rejected" ? (
                  <button type="button" onClick={secrets}>
                    {t("changePassword")}
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => navigate({ page: "log", id: profile.id })}
                  >
                    {t("viewLog")}
                  </button>
                )}
              </>
            )}
          </div>
        </Notice>
      )}
    </article>
  );
}
