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
export type Snapshot = {
  version: string;
  demo: boolean;
  helper: "installed" | "missing" | "outdated";
  componentOperation?: "installing" | "removing" | "settling";
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
  | { type: "save_profile"; profile: Profile }
  | { type: "save_secrets"; id: string; password: string; psk: string }
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
