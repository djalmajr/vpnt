import type { OvpnSettings, VpnKind, Profile as VpnProfile } from "./model";
import { isLinuxPlatform } from "./platform";

// The remote port is a real configuration field: the backend consumes
// `profile.port` as the remote port (StrongSwan IKE defaults to 500), so the
// default must follow the profile kind while the field stays editable.
const defaultPorts = { ipsec: 500, ssl: 443, ovpn: 1194 } as const;

export const blankOvpn = (): OvpnSettings => ({
  certificateId: "",
  module: isLinuxPlatform() ? "/usr/lib/libserproidp11.so" : "",
  tls: "pkcs1_only",
});

export function blankProfile(kind: VpnKind): VpnProfile {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return {
    id: Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
      "",
    ),
    kind,
    ...(kind === "ovpn" ? { ovpn: blankOvpn() } : {}),
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
