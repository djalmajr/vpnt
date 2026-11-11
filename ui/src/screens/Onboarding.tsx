import { useState } from "react";
import { Header, Icon, type T } from "../components/common";
import type { Navigate, Run } from "../navigation";

export function Onboarding({
  navigate,
  run,
  t,
}: {
  navigate: Navigate;
  run: Run;
  t: T;
}) {
  const [details, setDetails] = useState(false);
  const [installing, setInstalling] = useState(false);
  return (
    <>
      <Header
        title={t(details ? "component" : "vpns")}
        back={() => (details ? setDetails(false) : navigate({ page: "panel" }))}
        t={t}
      />
      <div className="empty">
        <span className="primary-text">
          <Icon name={installing ? "loader" : "shield"} large />
        </span>
        <strong>
          {t(
            installing ? "installing" : details ? "component" : "welcomeTitle",
          )}
        </strong>
        <p>
          {t(
            installing
              ? "installConfirm"
              : details
                ? "installDetails"
                : "welcomeHint",
          )}
        </p>
        {!installing && (
          <div className="actions fill">
            {!details && (
              <button type="button" onClick={() => setDetails(true)}>
                {t("details")}
              </button>
            )}
            <button
              type="button"
              className="primary"
              onClick={() => {
                setInstalling(true);
                void run({ type: "install_helper" })
                  .then((ok) => {
                    if (ok) navigate({ page: "new" });
                  })
                  .finally(() => setInstalling(false));
              }}
            >
              {t("install")}
            </button>
          </div>
        )}
      </div>
    </>
  );
}
