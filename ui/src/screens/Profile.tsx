import { useState } from "react";
import { Dialog, Group, Header, Row, type T } from "../components/common";
import type { Profile as VpnProfile, VpnView } from "../model";
import type { Navigate, Run } from "../navigation";

function blankProfile(kind: "ipsec" | "ssl"): VpnProfile {
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
    port: 443,
    certificate: "",
    probeHost: "",
    probePort: 8443,
    probeMethod: "ping_tcp",
  };
}

export function Profile({
  vpn,
  kind,
  navigate,
  run,
  t,
  secrets,
  remove,
}: {
  vpn?: VpnView;
  kind?: "ipsec" | "ssl";
  navigate: Navigate;
  run: Run;
  t: T;
  secrets: () => void;
  remove: () => void;
}) {
  const [initial] = useState(
    () => vpn?.profile ?? blankProfile(kind ?? "ipsec"),
  );
  const [value, setValue] = useState(initial);
  const [networks, setNetworks] = useState(initial.networks.join(", "));
  const [discard, setDiscard] = useState(false);
  const [saving, setSaving] = useState(false);
  const dirty =
    JSON.stringify(value) !== JSON.stringify(initial) ||
    networks !== initial.networks.join(", ");
  const set = <K extends keyof VpnProfile>(key: K, next: VpnProfile[K]) =>
    setValue({ ...value, [key]: next });
  const back = () =>
    dirty ? setDiscard(true) : navigate({ page: "preferences" });
  const canSave =
    !!value.name.trim() &&
    !!value.gateway.trim() &&
    !!value.probeHost.trim() &&
    value.port > 0 &&
    value.port <= 65535 &&
    value.probePort > 0 &&
    value.probePort <= 65535 &&
    value.probePort !== 22 &&
    !saving;
  const input = (
    key: "name" | "gateway" | "username" | "certificate" | "probeHost",
    label: Parameters<T>[0],
    placeholder?: string,
  ) => (
    <label className="field">
      <span>{t(label)}</span>
      <input
        value={value[key]}
        disabled={saving}
        placeholder={placeholder}
        maxLength={key === "name" ? 120 : 253}
        onChange={(event) => set(key, event.target.value)}
        spellCheck={false}
        autoComplete="off"
      />
    </label>
  );
  return (
    <>
      <Header
        title={vpn?.profile.name ?? t("newVpn")}
        back={back}
        backDisabled={saving}
        t={t}
      />
      <form
        className="profile-form"
        aria-busy={saving}
        onSubmit={(event) => {
          event.preventDefault();
          if (canSave) {
            setSaving(true);
            void run({
              type: "save_profile",
              profile: {
                ...value,
                networks: networks
                  .split(",")
                  .map((network) => network.trim())
                  .filter(Boolean),
              },
            })
              .then((ok) => {
                if (ok) navigate({ page: "preferences" });
              })
              .finally(() => setSaving(false));
          }
        }}
      >
        <Group>
          {input("name", "name")}
          <label className="field">
            <span>{t("type")}</span>
            <select
              value={value.kind}
              disabled={saving}
              onChange={(event) =>
                set("kind", event.target.value as VpnProfile["kind"])
              }
            >
              <option value="ipsec">{t("ipsec")}</option>
              <option value="ssl">{t("ssl")}</option>
            </select>
          </label>
          {input("gateway", "gateway", "vpn.example.com")}
          {value.kind === "ssl" && (
            <label className="field">
              <span>{t("port")}</span>
              <input
                type="number"
                disabled={saving}
                min={1}
                max={65535}
                value={value.port || ""}
                onChange={(event) => set("port", Number(event.target.value))}
              />
            </label>
          )}
          {input("username", "username")}
          {value.kind === "ipsec" ? (
            <>
              <label className="field">
                <span>{t("networks")}</span>
                <input
                  value={networks}
                  disabled={saving}
                  placeholder="10.20.0.0/24"
                  onChange={(event) => setNetworks(event.target.value)}
                />
              </label>
              <p className="hint">{t("networksHint")}</p>
            </>
          ) : (
            <>
              {input("certificate", "certificate")}
              <p className="hint">{t("certificateHint")}</p>
            </>
          )}
        </Group>
        <h2 className="section-title">{t("tunnelTest")}</h2>
        <Group>
          {input("probeHost", "probeHost", "10.20.0.15")}
          <p className="hint">{t("probeHostHint")}</p>
          <label className="field">
            <span>{t("method")}</span>
            <select
              value={value.probeMethod}
              disabled={saving}
              onChange={(event) =>
                set(
                  "probeMethod",
                  event.target.value as VpnProfile["probeMethod"],
                )
              }
            >
              <option value="ping_tcp">{t("pingTcp")}</option>
              <option value="tcp">{t("tcp")}</option>
            </select>
          </label>
          <label className="field">
            <span>{t("tcpPort")}</span>
            <input
              type="number"
              disabled={saving}
              min={1}
              max={65535}
              value={value.probePort || ""}
              aria-invalid={value.probePort === 22}
              onChange={(event) => set("probePort", Number(event.target.value))}
            />
          </label>
          <p className="hint">{t("probePortHint")}</p>
        </Group>
        {!!vpn && (
          <>
            <h2 className="section-title">{t("secrets")}</h2>
            <Group>
              {value.kind === "ipsec" && (
                <Row
                  label={t("psk")}
                  hint={t(vpn.hasPsk ? "stored" : "notStored")}
                >
                  <button type="button" onClick={secrets} disabled={saving}>
                    {t(vpn.hasPsk ? "change" : "provide")}
                  </button>
                </Row>
              )}
              <Row
                label={t("password")}
                hint={t(vpn.hasPassword ? "stored" : "notStored")}
              >
                <button type="button" onClick={secrets} disabled={saving}>
                  {t(vpn.hasPassword ? "change" : "provide")}
                </button>
              </Row>
            </Group>
          </>
        )}
        <p className="hint" role="status">
          {t(saving ? "adminPending" : "saveRequiresAdmin")}
        </p>
        <div className="spread">
          {vpn ? (
            <button
              type="button"
              className="danger"
              onClick={remove}
              disabled={saving}
            >
              {t("removeVpn")}
            </button>
          ) : (
            <span />
          )}
          <button type="submit" className="primary" disabled={!canSave}>
            {t("save")}
          </button>
        </div>
      </form>
      {discard && (
        <Dialog title={t("discardTitle")} close={() => setDiscard(false)} t={t}>
          <p>{t("discardHint")}</p>
          <div className="actions end">
            <button type="button" onClick={() => setDiscard(false)}>
              {t("keepEditing")}
            </button>
            <button
              type="button"
              className="danger"
              onClick={() => navigate({ page: "preferences" })}
            >
              {t("discard")}
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
