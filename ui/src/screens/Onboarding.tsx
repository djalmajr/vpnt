import { Header, Icon, type T } from "../components/common";
import type { Navigate } from "../navigation";

export function Onboarding({
  navigate,
  install,
  busy,
  outdated = false,
  t,
}: {
  navigate: Navigate;
  install: () => void;
  busy: boolean;
  outdated?: boolean;
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
        <strong>
          {t(busy ? "componentBusy" : outdated ? "update" : "welcomeTitle")}
        </strong>
        <p>
          {t(
            busy
              ? "componentSettling"
              : outdated
                ? "helperOutdated"
                : "welcomeHint",
          )}
        </p>
        {!busy && (
          <div className="actions fill">
            <button type="button" className="primary" onClick={install}>
              {t(outdated ? "update" : "install")}
            </button>
          </div>
        )}
      </div>
    </>
  );
}
