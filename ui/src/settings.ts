import type { LocalePreference } from "./i18n";
import type { NativePreferences } from "./model";

/** Locally owned preferences: they change rendering, not native behavior. */
export type LocalSettings = {
  locale: LocalePreference;
  theme: "system" | "light" | "dark";
};
/** Rendering view model: local values merged with the backend snapshot. */
export type Settings = LocalSettings & NativePreferences;

export const defaultSettings: LocalSettings = {
  locale: "system",
  theme: "system",
};
/**
 * Rendering fallback used only before the first snapshot (or poll) arrives.
 * Never persisted, so a saved local value never replays a native choice; once a
 * real snapshot exists, its `preferences` are the only source.
 */
export const defaultPreferences: NativePreferences = {
  interval: 10,
  notify: true,
  reconnect: false,
  startup: false,
};
const storageKey = "vpnt.preferences.v1";
export function loadSettings(): LocalSettings {
  try {
    const value = JSON.parse(localStorage.getItem(storageKey) ?? "null");
    if (!value || typeof value !== "object") return defaultSettings;
    // Native fields written by earlier versions are deliberately ignored: the
    // backend snapshot is the only source for interval/notify/reconnect/startup.
    return {
      locale: ["system", "pt-BR", "en-US"].includes(value.locale)
        ? value.locale
        : "system",
      theme: ["system", "light", "dark"].includes(value.theme)
        ? value.theme
        : "system",
    };
  } catch {
    return defaultSettings;
  }
}
export function saveSettings(settings: LocalSettings) {
  try {
    localStorage.setItem(
      storageKey,
      JSON.stringify({ locale: settings.locale, theme: settings.theme }),
    );
  } catch {
    /* A full data store must not prevent operating the panel. */
  }
}
/** Fields the user changed relative to what is rendered. An empty patch means
 * the change is purely local (locale/theme) and must not reach the bridge. */
export function preferencesDiff(
  current: Settings,
  next: Settings,
): Partial<NativePreferences> {
  const patch: Partial<NativePreferences> = {};
  if (next.interval !== current.interval) patch.interval = next.interval;
  if (next.notify !== current.notify) patch.notify = next.notify;
  if (next.reconnect !== current.reconnect) patch.reconnect = next.reconnect;
  if (next.startup !== current.startup) patch.startup = next.startup;
  return patch;
}
