import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "./bridge";
import { commandFlow } from "./commandFlow";
import type { T } from "./components/common";
import { type MessageKey, resolveLocale, translate } from "./i18n";
import { active, type Snapshot } from "./model";
import type { Route } from "./navigation";
import { observePanelHeight } from "./panelSizing";
import { createPreferencesFlow } from "./preferencesFlow";
import {
  defaultPreferences,
  loadSettings,
  preferencesDiff,
  type Settings,
  saveSettings,
} from "./settings";

/**
 * Only the automatic first-use screen is derived from an earlier snapshot; a
 * later authoritative `installed` confirmation leaves it stale (it keeps
 * offering Install after a late successful installation). Every explicit route
 * is the user's intent and must never be taken over by a snapshot: only
 * `onboarding` is reconciled, and only from a real (non-demo) snapshot that
 * confirms installation or reports that an earlier session is still finishing.
 */
export function reconcileRoute(previous: Route, snapshot: Snapshot): Route {
  if (
    snapshot.demo ||
    (snapshot.helper !== "installed" &&
      snapshot.helper !== "previous_session_finishing")
  )
    return previous;
  return previous.page === "onboarding" ? { page: "panel" } : previous;
}

export function reconcileComponentError(
  error: MessageKey | undefined,
  snapshot: Snapshot,
): MessageKey | undefined {
  if (
    !snapshot.demo &&
    snapshot.helper === "installed" &&
    (error === "componentExpired" || error === "componentUnconfirmed")
  ) {
    return undefined;
  }
  return error;
}

export type InstallSource = "panel" | "onboarding" | "preferences";
export type InstallAttempt = { source: InstallSource; updating: boolean };

export function componentBlocked(snapshot: Snapshot): boolean {
  return (
    snapshot.helper === "previous_session_finishing" ||
    snapshot.vpns.some(
      (vpn) =>
        active(vpn.state) || vpn.state === "disconnecting" || vpn.cleaning,
    )
  );
}

export function useAppState() {
  const [local, setLocal] = useState(loadSettings);
  const locale = resolveLocale(local.locale, navigator.languages);
  const t: T = useCallback(
    (key, values) => translate(locale, key, values),
    [locale],
  );
  const [systemDark, setSystemDark] = useState(
    () => matchMedia("(prefers-color-scheme: dark)").matches,
  );
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const receivedSnapshot = useRef<Snapshot | undefined>(undefined);
  const liveRef = useRef(true);
  const preferencesRef = useRef<
    ReturnType<typeof createPreferencesFlow> | undefined
  >(undefined);
  const [preferencesPending, setPreferencesPending] = useState(false);
  const [route, navigate] = useState<Route>({ page: "panel" });
  const [error, setError] = useState<MessageKey>();
  const [componentAction, setComponentAction] = useState<"remove">();
  const [installAttempt, setInstallAttempt] = useState<InstallAttempt>();
  const [installFailure, setInstallFailure] = useState<InstallSource>();
  const installLock = useRef(false);
  const [modal, setModal] = useState<{
    type: "secrets" | "remove";
    id: string;
    connect?: boolean;
  }>();
  const firstSnapshot = useRef(true);
  const receive = useCallback((snapshot: Snapshot) => {
    receivedSnapshot.current = snapshot;
    if (snapshot.helper === "previous_session_finishing")
      setComponentAction(undefined);
    if (!snapshot.demo && snapshot.helper === "installed")
      setInstallFailure(undefined);
    setError((previous) => reconcileComponentError(previous, snapshot));
    setSnapshot((previous) =>
      JSON.stringify(previous) === JSON.stringify(snapshot)
        ? previous
        : snapshot,
    );
    if (firstSnapshot.current) {
      firstSnapshot.current = false;
      if (
        !snapshot.demo &&
        (snapshot.helper === "missing" || snapshot.helper === "outdated") &&
        !snapshot.vpns.length
      )
        navigate({ page: "onboarding" });
    }
    // A successful in-flight install reconciles its own origin below. Capture
    // this before scheduling the updater: the lock may be released before React
    // runs it, and an automatic onboarding redirect would lose that origin.
    const installing = installLock.current;
    navigate((previous) =>
      installing && snapshot.helper !== "previous_session_finishing"
        ? previous
        : reconcileRoute(previous, snapshot),
    );
    // Fresh authoritative state: flush preference intent that was waiting for
    // one (first snapshot, or a reply that could not be reconciled in place).
    void preferencesRef.current?.sync();
  }, []);
  const flow = useMemo(
    () =>
      commandFlow(invoke, receive, (code) => {
        const keys: Record<string, MessageKey> = {
          not_implemented: "notImplemented",
          invalid_name: "invalidName",
          invalid_gateway: "invalidGateway",
          invalid_network: "invalidNetwork",
          invalid_probe: "invalidProbe",
          backend_unavailable: "backendUnavailable",
          admin_busy: "adminBusy",
          profile_busy: "profileBusy",
          preferences_unavailable: "preferencesUnavailable",
          startup_requires_approval: "startupRequiresApproval",
          startup_unavailable: "startupUnavailable",
          admin_expired: "adminExpired",
          admin_canceled: "adminUnconfirmed",
          admin_unconfirmed: "adminUnconfirmed",
          admin_incompatible: "adminIncompatible",
          secret_cleanup_failed: "secretCleanupFailed",
          component_busy: "componentBusy",
          previous_session_finishing: "previousSessionFinishing",
          component_expired: "componentExpired",
          component_canceled: "componentUnconfirmed",
          component_unconfirmed: "componentUnconfirmed",
          component_incompatible: "componentIncompatible",
        };
        setError(code ? (keys[code] ?? "error") : undefined);
      }),
    [receive],
  );
  const installComponent = useCallback(
    async (source: InstallSource) => {
      const current = receivedSnapshot.current;
      if (
        !current ||
        current.helper === "installed" ||
        current.componentOperation ||
        componentBlocked(current) ||
        installLock.current
      )
        return;
      installLock.current = true;
      setInstallAttempt({ source, updating: current.helper === "outdated" });
      setInstallFailure(undefined);
      try {
        const ok = await flow.run({ type: "install_helper" });
        if (!liveRef.current) return;
        if (ok) {
          const destination: Route = {
            page: receivedSnapshot.current?.vpns.length ? "panel" : "new",
          };
          navigate((previous) =>
            previous.page === source ? destination : previous,
          );
        } else {
          setInstallFailure(source);
        }
      } finally {
        installLock.current = false;
        if (liveRef.current) setInstallAttempt(undefined);
      }
    },
    [flow],
  );
  const preferences = useMemo(
    () =>
      createPreferencesFlow({
        authoritative: () => receivedSnapshot.current?.preferences,
        send: async (preferences) => {
          const result = await flow.dispatch({
            type: "set_preferences",
            preferences,
          });
          // A write timeout/expiry is not "vpnt is unreachable": the panel is
          // reachable and the host may still apply it.
          if (
            !result.ok &&
            !result.superseded &&
            result.code === "backend_unavailable"
          )
            setError("preferencesNotConfirmed");
          return result;
        },
        refresh: () =>
          liveRef.current
            ? flow.poll(() => liveRef.current)
            : Promise.resolve(false),
        onPendingChange: setPreferencesPending,
      }),
    [flow],
  );
  preferencesRef.current = preferences;
  // Live only while the screen is mounted: the cleanup discards queued changes
  // and the setup revives the same instance (React StrictMode re-runs both).
  useEffect(() => {
    liveRef.current = true;
    preferences.setLive(true);
    return () => {
      liveRef.current = false;
      preferences.setLive(false);
    };
  }, [preferences]);
  // The snapshot owns the four native values (required by the shared model);
  // the defaults apply only before the first snapshot arrives. Locale/theme
  // stay local; `preferencesPending` is transient rendering state.
  const settings: Settings & { preferencesPending: boolean } = {
    ...local,
    ...(snapshot?.preferences ?? defaultPreferences),
    preferencesPending,
  };
  const rendered = useRef(settings);
  rendered.current = settings;
  const updateSettings = useCallback(
    (next: Settings) => {
      const current = rendered.current;
      if (next.locale !== current.locale || next.theme !== current.theme)
        setLocal((previous) => ({
          ...previous,
          locale: next.locale,
          theme: next.theme,
        }));
      const change = preferencesDiff(current, next);
      if (Object.keys(change).length) void preferences.update(change);
    },
    [preferences],
  );
  useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      await flow.poll(() => !disposed);
      if (!disposed) timer = setTimeout(() => void poll(), 500);
    };
    void poll();
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [flow]);
  useEffect(() => {
    saveSettings(local);
    document.documentElement.lang = locale;
  }, [local, locale]);
  useEffect(() => {
    const media = matchMedia("(prefers-color-scheme: dark)");
    const changed = () => setSystemDark(media.matches);
    media.addEventListener("change", changed);
    return () => media.removeEventListener("change", changed);
  }, []);
  const dark =
    settings.theme === "dark" || (settings.theme === "system" && systemDark);
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);
  useEffect(() => {
    const onEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || event.defaultPrevented) return;
      // Modal Escape belongs to the dialog; it must not hide the native panel.
      if (document.querySelector("dialog[open]")) return;
      if (window.ipc) {
        void invoke({ type: "hide" }).catch(() => {});
      }
    };
    document.addEventListener("keydown", onEscape);
    return () => document.removeEventListener("keydown", onEscape);
  }, []);
  // Reports the panel height, temporarily raised while the Options menu needs
  // room (see `panelSizing`); the cleanup releases the observer and the marker.
  useEffect(() => {
    if (!window.ipc) return;
    return observePanelHeight((height) => {
      void invoke({ type: "resize", height }).catch(() => {});
    });
  }, []);
  const selected = useMemo(
    () =>
      route.page === "profile"
        ? snapshot?.vpns.find((vpn) => vpn.profile.id === route.id)
        : undefined,
    [route, snapshot],
  );
  const modalVpn = snapshot?.vpns.find((vpn) => vpn.profile.id === modal?.id);
  return {
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
    componentAction,
    setComponentAction,
    installAttempt,
    installFailure,
    installComponent,
    run: flow.run,
  };
}
