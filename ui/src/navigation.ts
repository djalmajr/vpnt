import type { Command } from "./model";
export type ProfileOrigin = "home" | "preferences";
export type Route =
  | { page: "panel" | "preferences" | "about" | "onboarding" }
  | { page: "new"; origin?: ProfileOrigin }
  | {
      page: "profile";
      id?: string;
      kind?: "ipsec" | "ssl";
      origin?: ProfileOrigin;
    }
  | { page: "log"; id?: string };
export function profileOriginRoute(origin?: ProfileOrigin): Route {
  return { page: origin === "preferences" ? "preferences" : "panel" };
}
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
