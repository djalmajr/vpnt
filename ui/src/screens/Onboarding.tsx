import { useState } from "react";
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
  const [details, setDetails] = useState(false);
  return (
    <>
      <Header
        title={t(details ? "component" : "vpns")}
        back={() => (details ? setDetails(false) : navigate({ page: "panel" }))}
        t={t}
      />
      <div className="empty">
        <span className="primary-text">
          <Icon name={busy ? "loader" : "shield"} large />
        </span>
        <strong>
          {t(busy ? "componentBusy" : details ? "component" : "welcomeTitle")}
        </strong>
        <p>
          {t(
            busy
              ? "componentSettling"
              : details
                ? "installDetails"
                : "welcomeHint",
          )}
        </p>
        {!busy && (
          <div className="actions fill">
            {!details && (
              <button type="button" onClick={() => setDetails(true)}>
                {t("details")}
              </button>
            )}
            <button type="button" className="primary" onClick={install}>
              {t("install")}
            </button>
          </div>
        )}
      </div>
    </>
  );
}
