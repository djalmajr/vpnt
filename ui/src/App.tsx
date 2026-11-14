import { ComponentDialog, ComponentStatus } from "./components/ComponentDialog";
import { Group, Header, Icon, Notice } from "./components/common";
import { Footer } from "./components/Footer";
import { RemoveDialog } from "./components/RemoveDialog";
import { SecretsDialog } from "./components/SecretsDialog";
import { VpnCard } from "./components/VpnCard";
import { states } from "./model";
import { Log } from "./screens/Log";
import { Onboarding } from "./screens/Onboarding";
import { Preferences } from "./screens/Preferences";
import { Profile } from "./screens/Profile";
import { useAppState } from "./useAppState";

export function App() {
  const {
    settings,
    updateSettings,
    locale,
    t,
    snapshot,
    route,
    navigate,
    error,
    setError,
    modal,
    setModal,
    selected,
    modalVpn,
    run,
    componentAction,
    setComponentAction,
    componentInstalled,
  } = useAppState();
  return (
    <main id="panel" className="panel">
      {snapshot?.demo && (
        <aside className="demo-label" title={t("demoHint")}>
          {t("demo")}
        </aside>
      )}
      {error && (
        <Notice tone="error">
          <p role="alert">{t(error)}</p>
          <button type="button" onClick={() => setError(undefined)}>
            {t("close")}
          </button>
        </Notice>
      )}
      {!snapshot ? (
        <>
          <Header title={t("appName")} t={t} />
          <p className="hint">{t("loading")}</p>
        </>
      ) : (
        <>
          <ComponentStatus snapshot={snapshot} t={t} />
          {route.page === "panel" && (
            <>
              <Header
                title={t("vpns")}
                action={
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={t("preferences")}
                    onClick={() => navigate({ page: "preferences" })}
                  >
                    <Icon name="settings" />
                  </button>
                }
                t={t}
              />
              {snapshot.helper !== "installed" && (
                <Notice>
                  <p>
                    {t(
                      snapshot.helper === "outdated"
                        ? "helperOutdated"
                        : "helperBanner",
                    )}
                  </p>
                  <button
                    type="button"
                    className="primary"
                    disabled={!!snapshot.componentOperation}
                    onClick={() => navigate({ page: "onboarding" })}
                  >
                    {t(snapshot.helper === "outdated" ? "update" : "install")}
                  </button>
                </Notice>
              )}
              {snapshot.vpns.length ? (
                snapshot.vpns.map((vpn) => (
                  <VpnCard
                    key={vpn.profile.id}
                    vpn={vpn}
                    t={t}
                    run={run}
                    navigate={navigate}
                    secrets={() =>
                      setModal({
                        type: "secrets",
                        id: vpn.profile.id,
                        connect: true,
                      })
                    }
                  />
                ))
              ) : (
                <div className="empty">
                  <Icon name="shield" large />
                  <strong>{t("emptyTitle")}</strong>
                  <p>{t("emptyHint")}</p>
                  <button
                    type="button"
                    className="primary block"
                    onClick={() => navigate({ page: "new" })}
                  >
                    {t("addVpn")}
                  </button>
                </div>
              )}
            </>
          )}
          {route.page === "preferences" && (
            <Preferences
              snapshot={snapshot}
              settings={settings}
              update={updateSettings}
              navigate={navigate}
              removeComponent={() => setComponentAction("remove")}
              t={t}
            />
          )}
          {route.page === "new" && (
            <>
              <Header
                title={t("newVpn")}
                back={() => navigate({ page: "preferences" })}
                t={t}
              />
              <h2 className="section-title">{t("chooseType")}</h2>
              {(["ipsec", "ssl"] as const).map((kind) => (
                <Group key={kind}>
                  <button
                    type="button"
                    className="profile-row"
                    onClick={() => navigate({ page: "profile", kind })}
                  >
                    <span>
                      {t(kind)}
                      <small>
                        {t(kind === "ipsec" ? "ipsecHint" : "sslHint")}
                      </small>
                    </span>
                    <Icon name="chevron" />
                  </button>
                </Group>
              ))}
              <p className="hint">{t("programsHint")}</p>
            </>
          )}
          {route.page === "profile" && (
            <Profile
              key={route.id ?? route.kind}
              vpn={selected}
              kind={route.kind}
              navigate={navigate}
              run={run}
              t={t}
              secrets={() =>
                selected &&
                setModal({ type: "secrets", id: selected.profile.id })
              }
              remove={() =>
                selected &&
                setModal({ type: "remove", id: selected.profile.id })
              }
            />
          )}
          {route.page === "log" && (
            <Log
              snapshot={snapshot}
              id={route.id}
              navigate={navigate}
              run={run}
              t={t}
              locale={locale}
            />
          )}
          {route.page === "onboarding" && (
            <Onboarding
              navigate={navigate}
              install={() => setComponentAction("install")}
              busy={!!snapshot.componentOperation}
              t={t}
            />
          )}
          {route.page === "about" && (
            <>
              <Header
                title={t("about")}
                back={() => navigate({ page: "panel" })}
                t={t}
              />
              <div className="empty">
                <span className="primary-text">
                  <Icon name="shield" large />
                </span>
                <strong>{t("version", { version: snapshot.version })}</strong>
                <p>{t("aboutText")}</p>
                <a
                  className="button"
                  href="https://github.com/djalmajr/vpnt"
                  target="_blank"
                  rel="noreferrer"
                  onClick={(event) => {
                    if (window.ipc) {
                      event.preventDefault();
                      void run({ type: "open_project" });
                    }
                  }}
                >
                  {t("projectPage")}
                </a>
              </div>
            </>
          )}
          {snapshot.demo && route.page === "panel" && (
            <details className="demo-controls">
              <summary>{t("demoState")}</summary>
              <p className="hint">{t("demoHint")}</p>
              {snapshot.vpns.map((vpn) => (
                <label className="field" key={vpn.profile.id}>
                  <span>{vpn.profile.name}</span>
                  <select
                    aria-label={`${vpn.profile.name}: ${t("demoState")}`}
                    value={vpn.state}
                    onChange={(event) =>
                      void run({
                        type: "set_demo_state",
                        id: vpn.profile.id,
                        state: event.target.value as (typeof states)[number],
                      })
                    }
                  >
                    {states.map((state) => (
                      <option key={state} value={state}>
                        {t(`state.${state}`)}
                      </option>
                    ))}
                  </select>
                </label>
              ))}
            </details>
          )}
          {!["profile", "log", "new"].includes(route.page) && (
            <Footer snapshot={snapshot} navigate={navigate} run={run} t={t} />
          )}
          {modal &&
            modalVpn &&
            (modal.type === "secrets" ? (
              <SecretsDialog
                vpn={modalVpn}
                connect={!!modal.connect}
                run={run}
                close={() => setModal(undefined)}
                t={t}
              />
            ) : (
              <RemoveDialog
                vpn={modalVpn}
                run={run}
                close={() => setModal(undefined)}
                removed={() => {
                  setModal(undefined);
                  navigate({ page: "preferences" });
                }}
                t={t}
              />
            ))}
          {componentAction && (
            <ComponentDialog
              kind={componentAction}
              run={run}
              close={() => setComponentAction(undefined)}
              installed={componentInstalled}
              t={t}
            />
          )}
        </>
      )}
    </main>
  );
}
