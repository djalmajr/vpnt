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
  const { state, profile } = vpn;
  const busy = [
    "connecting",
    "reconnecting",
    "disconnecting",
    "verifying",
  ].includes(state);
  const disabled = [
    "offline",
    "helper_missing",
    "missing_program",
    "disconnecting",
  ].includes(state);
  const cancelable = state === "connecting" || state === "reconnecting";
  const missingSecret = state === "missing_secret";
  const staticBody = cancelable || missingSecret;
  const CardBody = staticBody ? "div" : "button";
  const Switch = missingSecret ? "button" : "span";
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
  const principal = () => {
    if (staticBody) return;
    if (state === "unresponsive") {
      void run({ type: "reconnect", id: profile.id });
      return;
    }
    // The user clicked what the card shows, so the command names the direction
    // instead of re-reading the latest snapshot (which may already be off).
    void run({ type: on ? "disconnect" : "connect", id: profile.id });
  };
  return (
    <article className="vpn-card" data-testid={`vpn-card-${profile.id}`}>
      <CardBody
        type={staticBody ? undefined : "button"}
        className="card-toggle"
        disabled={staticBody ? undefined : disabled}
        onClick={staticBody ? undefined : principal}
        aria-label={
          staticBody ? undefined : `${profile.name}: ${t(`state.${state}`)}`
        }
        aria-pressed={staticBody ? undefined : on}
      >
        <span className="card-heading">
          <span className="identity">
            <strong>{profile.name}</strong>
            <small>
              {t(profile.kind)} ·{" "}
              {profile.networks.join(", ") || t("fullTunnel")}
            </small>
          </span>
          <Switch
            type={missingSecret ? "button" : undefined}
            onClick={missingSecret ? secrets : undefined}
            aria-label={
              missingSecret
                ? `${profile.name}: ${t("providePassword")}`
                : undefined
            }
            aria-hidden={missingSecret ? undefined : true}
            className={`switch ${on ? "on" : ""} ${busy || disabled ? "dim" : ""}`}
          >
            <span />
          </Switch>
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
      </CardBody>
      {hint && (
        <Notice tone={danger ? "error" : "warn"}>
          <p>{t(hint)}</p>
          <div className="actions">
            {state === "missing_program" ? (
              <button
                type="button"
                onClick={() => void run({ type: "probe", id: profile.id })}
              >
                {t("refresh")}
              </button>
            ) : (
              <>
                <button
                  type="button"
                  className="primary"
                  onClick={() =>
                    void run({ type: "reconnect", id: profile.id })
                  }
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
