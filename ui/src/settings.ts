import type { LocalePreference } from "./i18n";

export type Settings = {
  locale: LocalePreference;
  theme: "system" | "light" | "dark";
  interval: number;
  notify: boolean;
  reconnect: boolean;
  startup: boolean;
};
export const defaultSettings: Settings = {
  locale: "system",
  theme: "system",
  interval: 10,
  notify: true,
  reconnect: false,
  startup: false,
};
const storageKey = "vpnt.preferences.v1";
export function loadSettings(): Settings {
  try {
    const value = JSON.parse(localStorage.getItem(storageKey) ?? "null");
    if (!value || typeof value !== "object") return defaultSettings;
    return {
      locale: ["system", "pt-BR", "en-US"].includes(value.locale)
        ? value.locale
        : "system",
      theme: ["system", "light", "dark"].includes(value.theme)
        ? value.theme
        : "system",
      interval: [10, 30, 60].includes(value.interval) ? value.interval : 10,
      notify: typeof value.notify === "boolean" ? value.notify : true,
      reconnect: value.reconnect === true,
      startup: value.startup === true,
    };
  } catch {
    return defaultSettings;
  }
}
export function saveSettings(settings: Settings) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(settings));
  } catch {
    /* A full data store must not prevent operating the panel. */
  }
}
