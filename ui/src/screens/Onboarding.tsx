import { Header, Icon, type T } from "../components/common";
import type { Navigate } from "../navigation";

export function Onboarding({
  navigate,
  install,
  busy,
  t,
}: {
  navigate: Navigate;
  install: () => void;
  busy: boolean;
  t: T;
}) {
  return (
    <>
      <Header
        title={t("vpns")}
        back={() => navigate({ page: "panel" })}
        t={t}
      />
      <div className="empty">
        <span className="primary-text">
          <Icon name={busy ? "loader" : "shield"} large />
        </span>
        <strong>{t(busy ? "componentBusy" : "welcomeTitle")}</strong>
        <p>{t(busy ? "componentSettling" : "welcomeHint")}</p>
        {!busy && (
          <div className="actions fill">
            <button type="button" className="primary" onClick={install}>
              {t("install")}
            </button>
          </div>
        )}
      </div>
    </>
  );
}
