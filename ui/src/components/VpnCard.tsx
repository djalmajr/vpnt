import { useRef, useState } from "react";
import { active, type VpnView } from "../model";
import type { Navigate, Run } from "../navigation";
import { Icon, Notice, type T } from "./common";

function VerifyCleanup({
  id,
  t,
  run,
  cleaning,
  cleanupVerifying,
}: {
  id: string;
  t: T;
  run: Run;
  cleaning: boolean;
  cleanupVerifying: boolean;
}) {
  const [pending, setPending] = useState(false);
  const inFlight = useRef(false);
  const busy = pending || cleanupVerifying;
  const verify = async () => {
    if (cleaning || cleanupVerifying || inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    try {
      await run({ type: "probe", id });
    } finally {
      inFlight.current = false;
      setPending(false);
    }
  };
  return (
    <button
      type="button"
      className="primary"
      disabled={cleaning || busy}
      aria-busy={busy || undefined}
      onClick={() => void verify()}
    >
      {busy && <Icon name="loader" />}
      {t("checkAgain")}
    </button>
  );
}

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
    [
      "offline",
      "helper_missing",
      "missing_program",
      "disconnecting",
      "cleanup_unconfirmed",
    ].includes(state);
  const cancelable = state === "connecting" || state === "reconnecting";
  const missingSecret = state === "missing_secret";
  const on = active(state);
  const warning = [
    "unresponsive",
    "dropped",
    "missing_secret",
    "missing_program",
    "cleanup_unconfirmed",
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
    state === "cleanup_unconfirmed"
      ? "cleanupUnconfirmedHint"
      : state === "unresponsive"
        ? "staleHint"
        : state === "dropped"
          ? vpn.failure && vpn.failure.step !== "health"
            ? "failedAtHint"
            : "droppedHint"
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
    // Only the chevron icon-button navigates: the body is not clickable and
    // carries no keyboard or pointer affordance of its own.
    <article className="vpn-card" data-testid={`vpn-card-${profile.id}`}>
      <div className="card-body">
        <span className="card-heading">
          <span className="identity">
            <strong>{profile.name}</strong>
            <small>
              {t(profile.kind)} ·{" "}
              {profile.networks.length
                ? profile.networks.join(", ")
                : t(profile.kind === "ssl" ? "gatewayRoutes" : "fullTunnel")}
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
              onClick={() =>
                navigate({ page: "profile", id: profile.id, origin: "home" })
              }
            >
              <Icon name="chevron" />
            </button>
          </span>
        </span>
        {!hint && (
          <span className="card-state">
            <span className="status-line">
              <span className={color}>
                <span className="dot" />
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
                <Icon name="loader" />
                {t("cancel")}
              </button>
            )}
          </span>
        )}
      </div>
      {hint && (
        <Notice tone={danger ? "error" : "warn"}>
          {state === "cleanup_unconfirmed" && (
            <strong>{t("state.cleanup_unconfirmed")}</strong>
          )}
          <p>
            {t(
              hint,
              vpn.failure ? { step: t(`step.${vpn.failure.step}`) } : {},
            )}
          </p>
          {cleaning && (
            <p id={cleanupId} role="status">
              {t("cleanupHint")}
            </p>
          )}
          <div className="actions">
            {state === "cleanup_unconfirmed" ? (
              <VerifyCleanup
                id={profile.id}
                t={t}
                run={run}
                cleaning={cleaning}
                cleanupVerifying={vpn.cleanupVerifying}
              />
            ) : state === "missing_program" ? (
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
