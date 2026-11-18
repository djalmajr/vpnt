import { useCallback, useEffect, useRef, useState } from "react";
import {
  ComponentDialog,
  ComponentStatus,
  InstallButton,
} from "./components/ComponentDialog";
import { Group, Header, Icon, Notice } from "./components/common";
import { Footer } from "./components/Footer";
import { RemoveDialog } from "./components/RemoveDialog";
import { SecretsDialog } from "./components/SecretsDialog";
import { VpnCard } from "./components/VpnCard";
import { states } from "./model";
import {
  type Navigate,
  type NavigationGuard,
  profileOriginRoute,
} from "./navigation";
import { Log } from "./screens/Log";
import { Onboarding } from "./screens/Onboarding";
import { Preferences } from "./screens/Preferences";
import { Profile } from "./screens/Profile";
import { componentBlocked, useAppState } from "./useAppState";

export function App() {
  const {
    settings,
    updateSettings,
    locale,
    t,
    snapshot,
    route,
    navigate: commitNavigation,
    error,
    setError,
    modal,
    setModal,
    selected,
    modalVpn,
    run,
    componentAction,
    setComponentAction,
    installAttempt,
    installFailure,
    installComponent,
  } = useAppState();
  const panelRef = useRef<HTMLElement>(null);
  const [dismissedNotices, setDismissedNotices] = useState<
    Record<string, { state: string; identity: string }>
  >({});
  useEffect(() => {
    if (!snapshot) return;
    setDismissedNotices((previous) => {
      const current = new Map(
        snapshot.vpns.map((vpn) => [vpn.profile.id, vpn.state]),
      );
      const entries = Object.entries(previous).filter(
        ([id, notice]) => current.get(id) === notice.state,
      );
      return entries.length === Object.keys(previous).length
        ? previous
        : Object.fromEntries(entries);
    });
  }, [snapshot]);
  const installBusy = !!installAttempt || !!snapshot?.componentOperation;
  const installBlocked = snapshot ? componentBlocked(snapshot) : false;
  const updating = installAttempt?.updating ?? snapshot?.helper === "outdated";
  const [navigationGuard, registerNavigationGuard] =
    useState<NavigationGuard>();
  const navigate: Navigate = useCallback(
    (destination) => {
      const proceed = () => commitNavigation(destination);
      if (navigationGuard) navigationGuard.request(proceed);
      else proceed();
    },
    [commitNavigation, navigationGuard],
  );
  return (
    <main id="panel" className="panel" ref={panelRef} tabIndex={-1}>
      <div className="panel-content">
        {snapshot?.demo && (
          <aside className="demo-label" title={t("demoHint")}>
            {t("demo")}
          </aside>
        )}
        {error && (
          <Notice
            tone="error"
            t={t}
            onDismiss={() => {
              setError(undefined);
              const firstControl = panelRef.current?.querySelector<HTMLElement>(
                "button:not(:disabled):not(.notice-dismiss), select:not(:disabled), input:not(:disabled), a[href]",
              );
              (firstControl ?? panelRef.current)?.focus();
            }}
          >
            <p role="alert">{t(error)}</p>
          </Notice>
        )}
        {!snapshot ? (
          <>
            <Header title={t("appName")} t={t} />
            <p className="hint">{t("loading")}</p>
          </>
        ) : (
          <>
            <ComponentStatus
              snapshot={snapshot}
              installing={!!installAttempt}
              t={t}
            />
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
                {snapshot.helper === "previous_session_finishing" ? (
                  <Notice>
                    <p role="status">
                      <Icon name="loader" /> {t("helperPreviousSession")}
                    </p>
                  </Notice>
                ) : (
                  (snapshot.helper !== "installed" ||
                    installAttempt?.source === "panel") && (
                    <Notice>
                      <p>{t(updating ? "helperOutdated" : "helperBanner")}</p>
                      {installBlocked && (
                        <small>
                          {t(
                            updating
                              ? "componentUpdateBlocked"
                              : "componentInstallBlocked",
                          )}
                        </small>
                      )}
                      <InstallButton
                        className="primary"
                        install={() => void installComponent("panel")}
                        pending={installAttempt?.source === "panel"}
                        disabled={installBusy || installBlocked}
                        updating={updating}
                        failed={installFailure === "panel"}
                        t={t}
                      />
                    </Notice>
                  )
                )}
                {snapshot.vpns.length ? (
                  snapshot.vpns.map((vpn) => (
                    <VpnCard
                      key={vpn.profile.id}
                      vpn={vpn}
                      dismissed={
                        dismissedNotices[vpn.profile.id]?.identity ===
                        JSON.stringify([
                          vpn.state,
                          vpn.log.at(-1)?.timestamp ?? null,
                          vpn.log.length,
                        ])
                      }
                      dismiss={() =>
                        setDismissedNotices((previous) => ({
                          ...previous,
                          [vpn.profile.id]: {
                            state: vpn.state,
                            identity: JSON.stringify([
                              vpn.state,
                              vpn.log.at(-1)?.timestamp ?? null,
                              vpn.log.length,
                            ]),
                          },
                        }))
                      }
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
                      onClick={() => navigate({ page: "new", origin: "home" })}
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
                install={() => void installComponent("preferences")}
                installPending={installAttempt?.source === "preferences"}
                installBusy={installBusy}
                installBlocked={installBlocked}
                updating={updating}
                installFailed={installFailure === "preferences"}
                t={t}
              />
            )}
            {route.page === "new" && (
              <>
                <Header
                  title={t("newVpn")}
                  back={() => navigate(profileOriginRoute(route.origin))}
                  t={t}
                />
                <h2 className="section-title">{t("chooseType")}</h2>
                {(["ipsec", "ssl"] as const).map((kind) => (
                  <Group key={kind}>
                    <button
                      type="button"
                      className="profile-row"
                      onClick={() =>
                        navigate({
                          page: "profile",
                          kind,
                          origin: route.origin,
                        })
                      }
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
                origin={route.origin}
                navigate={navigate}
                registerNavigationGuard={registerNavigationGuard}
                saved={() => commitNavigation(profileOriginRoute(route.origin))}
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
                install={() => void installComponent("onboarding")}
                pending={installAttempt?.source === "onboarding"}
                busy={installBusy}
                blocked={installBlocked}
                outdated={updating}
                failed={installFailure === "onboarding"}
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
                    commitNavigation(
                      profileOriginRoute(
                        route.page === "profile" ? route.origin : undefined,
                      ),
                    );
                  }}
                  t={t}
                />
              ))}
            {componentAction && (
              <ComponentDialog
                run={run}
                close={() => setComponentAction(undefined)}
                t={t}
              />
            )}
          </>
        )}
      </div>
      {snapshot && (
        <Footer
          snapshot={snapshot}
          navigate={navigate}
          navigationBlocked={navigationGuard?.blocked}
          run={run}
          t={t}
        />
      )}
    </main>
  );
}
