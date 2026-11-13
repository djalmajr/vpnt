import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "./bridge";
import { commandFlow } from "./commandFlow";
import type { T } from "./components/common";
import { type MessageKey, resolveLocale, translate } from "./i18n";
import type { Snapshot } from "./model";
import type { Route } from "./navigation";
import { createPreferencesFlow } from "./preferencesFlow";
import {
  defaultPreferences,
  loadSettings,
  preferencesDiff,
  type Settings,
  saveSettings,
} from "./settings";

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
  const [componentAction, setComponentAction] = useState<
    "install" | "remove"
  >();
  const [modal, setModal] = useState<{
    type: "secrets" | "remove";
    id: string;
    connect?: boolean;
  }>();
  const firstSnapshot = useRef(true);
  const receive = useCallback((snapshot: Snapshot) => {
    receivedSnapshot.current = snapshot;
    setSnapshot((previous) =>
      JSON.stringify(previous) === JSON.stringify(snapshot)
        ? previous
        : snapshot,
    );
    if (firstSnapshot.current) {
      firstSnapshot.current = false;
      if (
        !snapshot.demo &&
        snapshot.helper !== "installed" &&
        !snapshot.vpns.length
      )
        navigate({ page: "onboarding" });
    }
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
          component_expired: "componentExpired",
          component_canceled: "componentUnconfirmed",
          component_unconfirmed: "componentUnconfirmed",
          component_incompatible: "componentIncompatible",
        };
        setError(code ? (keys[code] ?? "error") : undefined);
      }),
    [receive],
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
      const expanded =
        document.querySelector<HTMLDetailsElement>(".options[open]");
      if (expanded) {
        expanded.open = false;
        expanded.querySelector("summary")?.focus();
      } else if (window.ipc) {
        void invoke({ type: "hide" }).catch(() => {});
      }
    };
    document.addEventListener("keydown", onEscape);
    return () => document.removeEventListener("keydown", onEscape);
  }, []);
  useEffect(() => {
    if (!window.ipc) return;
    let previous = 0;
    const observer = new ResizeObserver(() => {
      const height = Math.ceil(
        document.getElementById("panel")?.getBoundingClientRect().height ?? 360,
      );
      if (height !== previous) {
        previous = height;
        void invoke({ type: "resize", height }).catch(() => {});
      }
    });
    const root = document.getElementById("root");
    if (root) observer.observe(root);
    return () => observer.disconnect();
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
    componentInstalled: () => {
      setComponentAction(undefined);
      navigate({
        page: receivedSnapshot.current?.vpns.length ? "panel" : "new",
      });
    },
    run: flow.run,
  };
}
