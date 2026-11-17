import { InstallButton } from "../components/ComponentDialog";
import { Header, Icon, type T } from "../components/common";
import type { Navigate } from "../navigation";

export function Onboarding({
  navigate,
  install,
  busy,
  pending,
  blocked,
  failed,
  outdated = false,
  t,
}: {
  navigate: Navigate;
  install: () => void;
  busy: boolean;
  pending: boolean;
  blocked: boolean;
  failed: boolean;
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
          <Icon name="shield" large />
        </span>
        <strong>{t(outdated ? "update" : "welcomeTitle")}</strong>
        <p>{t(outdated ? "helperOutdated" : "welcomeHint")}</p>
        {blocked && (
          <p>
            {t(outdated ? "componentUpdateBlocked" : "componentInstallBlocked")}
          </p>
        )}
        <div className="actions fill">
          <InstallButton
            className="primary"
            install={install}
            pending={pending}
            disabled={busy || blocked}
            updating={outdated}
            failed={failed}
            t={t}
          />
        </div>
      </div>
    </>
  );
}
