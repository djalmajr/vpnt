import type { Command } from "./model";
export type Route =
  | { page: "panel" | "preferences" | "about" | "new" | "onboarding" }
  | { page: "profile"; id?: string; kind?: "ipsec" | "ssl" }
  | { page: "log"; id?: string };
export type Navigate = (route: Route) => void;
/** A screen owns its pending edits; the App routes every requested exit here. */
export type NavigationGuard = {
  blocked: boolean;
  request: (proceed: () => void) => void;
};
export type RegisterNavigationGuard = (
  guard: NavigationGuard | undefined,
) => void;
export type Run = (command: Command) => Promise<boolean>;
