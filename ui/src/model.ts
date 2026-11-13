export const states = [
  "off",
  "connecting",
  "verifying",
  "connected",
  "unresponsive",
  "reconnecting",
  "disconnecting",
  "dropped",
  "credentials_rejected",
  "gateway_timeout",
  "missing_secret",
  "missing_program",
  "offline",
  "helper_missing",
] as const;
export type ConnectionState = (typeof states)[number];
export type Profile = {
  id: string;
  name: string;
  kind: "ipsec" | "ssl";
  gateway: string;
  username: string;
  networks: string[];
  port: number;
  certificate: string;
  probeHost: string;
  probePort: number;
  probeMethod: "ping_tcp" | "tcp";
};
export type VpnView = {
  profile: Profile;
  state: ConnectionState;
  hasPassword: boolean;
  hasPsk: boolean;
  log: { timestamp: number; state: ConnectionState }[];
};
export type NativePreferences = {
  interval: 10 | 30 | 60;
  notify: boolean;
  reconnect: boolean;
  startup: boolean;
};
export type Snapshot = {
  version: string;
  demo: boolean;
  helper: "installed" | "missing" | "outdated";
  componentOperation?: "installing" | "removing" | "settling";
  // Required: the backend that ships inside this app always produces it. The
  // UI only falls back to documented defaults before the first snapshot (or a
  // poll) has arrived; it never caches or replays a native choice.
  preferences: NativePreferences;
  vpns: VpnView[];
};
export type Command =
  | {
      type:
        | "get_snapshot"
        | "disconnect_all"
        | "install_helper"
        | "remove_helper"
        | "hide"
        | "open_project"
        | "quit";
    }
  | { type: "toggle" | "reconnect" | "probe" | "remove_profile"; id: string }
  // Explicit direction for the manual card action. `toggle` stays typed only as
  // the legacy contract: a toggle derives the command from the latest snapshot,
  // which may already disagree with what the user is looking at.
  | { type: "connect" | "disconnect"; id: string }
  | { type: "save_profile"; profile: Profile }
  | { type: "save_secrets"; id: string; password: string; psk: string }
  | { type: "set_preferences"; preferences: NativePreferences }
  | { type: "set_demo_state"; id: string; state: ConnectionState }
  | { type: "resize"; height: number };
export type Reply = { id: string; snapshot?: Snapshot; error?: string };
export const active = (state: ConnectionState) =>
  [
    "connecting",
    "verifying",
    "connected",
    "unresponsive",
    "reconnecting",
  ].includes(state);
