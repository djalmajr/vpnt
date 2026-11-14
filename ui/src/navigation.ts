import type { Command } from "./model";
export type Route =
  | { page: "panel" | "preferences" | "about" | "new" | "onboarding" }
  | { page: "profile"; id?: string; kind?: "ipsec" | "ssl" }
  | { page: "log"; id?: string };
export type Navigate = (route: Route) => void;
export type Run = (command: Command) => Promise<boolean>;
