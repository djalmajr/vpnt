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
            : state === "missing_secret"
              ? "secretHint"
              : state === "missing_program"
                ? "programHint"
                : null;
  const toggle = () => {
    if (state === "missing_secret") secrets();
    else
      void run({
        type: state === "unresponsive" ? "reconnect" : "toggle",
        id: profile.id,
      });
  };
  return (
    <article className="vpn-card" data-testid={`vpn-card-${profile.id}`}>
      <button
        type="button"
        className="card-toggle"
        disabled={disabled}
        onClick={toggle}
        aria-label={`${profile.name}: ${t(`state.${state}`)}`}
        aria-pressed={on}
      >
        <span className="card-heading">
          <span className="identity">
            <strong>{profile.name}</strong>
            <small>
              {t(profile.kind)} ·{" "}
              {profile.networks.join(", ") || t("fullTunnel")}
            </small>
          </span>
          <span
            aria-hidden="true"
            className={`switch ${on ? "on" : ""} ${busy || disabled ? "dim" : ""}`}
          >
            <span />
          </span>
        </span>
        <span className="card-state">
          <span className="status-line">
            <span className={color}>
              {busy ? <Icon name="loader" /> : <span className="dot" />}
            </span>
            <span>{t(`state.${state}`)}</span>
          </span>
          {["connecting", "reconnecting"].includes(state) && (
            <small>{t("cancel")}</small>
          )}
        </span>
      </button>
      {hint && (
        <Notice tone={danger ? "error" : "warn"}>
          <p>{t(hint)}</p>
          <div className="actions">
            {state === "missing_secret" ? (
              <button type="button" className="primary" onClick={secrets}>
                {t("providePassword")}
              </button>
            ) : state === "missing_program" ? (
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
                    onClick={() => void run({ type: "toggle", id: profile.id })}
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
