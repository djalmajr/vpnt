import type { Profile as VpnProfile } from "./model";

// The remote port is a real configuration field: the backend consumes
// `profile.port` as the remote port (StrongSwan IKE defaults to 500), so the
// default must follow the profile kind while the field stays editable.
const defaultPorts = { ipsec: 500, ssl: 443 } as const;

export function blankProfile(kind: "ipsec" | "ssl"): VpnProfile {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return {
    id: Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
      "",
    ),
    kind,
    name: "",
    gateway: "",
    username: "",
    networks: [],
    port: defaultPorts[kind],
    certificate: "",
    probeHost: "",
    probePort: 8443,
    probeMethod: "ping_tcp",
  };
}
