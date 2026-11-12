import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "./bridge";
import { commandFlow } from "./commandFlow";
import type { T } from "./components/common";
import { type MessageKey, resolveLocale, translate } from "./i18n";
import type { Snapshot } from "./model";
import type { Route } from "./navigation";
import { loadSettings, saveSettings } from "./settings";

export function useAppState() {
  const [settings, updateSettings] = useState(loadSettings);
  const locale = resolveLocale(settings.locale, navigator.languages);
  const t: T = useCallback(
    (key, values) => translate(locale, key, values),
    [locale],
  );
  const [systemDark, setSystemDark] = useState(
    () => matchMedia("(prefers-color-scheme: dark)").matches,
  );
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const receivedSnapshot = useRef<Snapshot | undefined>(undefined);
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
    saveSettings(settings);
    document.documentElement.lang = locale;
  }, [settings, locale]);
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
