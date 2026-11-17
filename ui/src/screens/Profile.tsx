import { useId, useLayoutEffect, useState } from "react";
import {
  Dialog,
  Group,
  Header,
  Row,
  Select,
  type T,
} from "../components/common";
import type { Profile as VpnProfile, VpnView } from "../model";
import {
  type Navigate,
  type ProfileOrigin,
  profileOriginRoute,
  type RegisterNavigationGuard,
  type Run,
} from "../navigation";
import { blankProfile } from "../profileDefaults";
import { hasShellExpression } from "../shellExpression";

export function Profile({
  vpn,
  kind,
  origin,
  navigate,
  registerNavigationGuard,
  saved,
  run,
  t,
  secrets,
  remove,
}: {
  vpn?: VpnView;
  kind?: "ipsec" | "ssl";
  origin?: ProfileOrigin;
  navigate: Navigate;
  registerNavigationGuard: RegisterNavigationGuard;
  saved: () => void;
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
  const [dnsDomains, setDnsDomains] = useState(
    (initial.dnsDomains ?? []).join(", "),
  );
  const [discard, setDiscard] = useState<() => void>();
  const [saving, setSaving] = useState(false);
  const dirty =
    JSON.stringify(value) !== JSON.stringify(initial) ||
    networks !== initial.networks.join(", ") ||
    dnsDomains !== (initial.dnsDomains ?? []).join(", ");
  const set = <K extends keyof VpnProfile>(key: K, next: VpnProfile[K]) =>
    setValue({ ...value, [key]: next });
  useLayoutEffect(() => {
    registerNavigationGuard({
      blocked: saving,
      request: (proceed) => {
        if (saving) return;
        if (dirty) setDiscard(() => proceed);
        else proceed();
      },
    });
    return () => registerNavigationGuard(undefined);
  }, [dirty, saving, registerNavigationGuard]);
  const back = () => navigate(profileOriginRoute(origin));
  const usernameErrorId = useId();
  const usernameError = hasShellExpression(value.username);
  const canSave =
    !usernameError &&
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
        aria-invalid={key === "username" && usernameError ? true : undefined}
        aria-describedby={
          key === "username" && usernameError ? usernameErrorId : undefined
        }
        disabled={saving}
        placeholder={placeholder}
        maxLength={key === "name" ? 120 : 253}
        onChange={(event) => set(key, event.target.value)}
        spellCheck={false}
        autoComplete="off"
      />
      {key === "username" && usernameError && (
        <small
          id={usernameErrorId}
          className="field-error danger-text"
          role="alert"
        >
          {t("usernameShellError")}
        </small>
      )}
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
            const profile = {
              ...value,
              networks: networks
                .split(",")
                .map((network) => network.trim())
                .filter(Boolean),
            };
            const domains =
              value.kind === "ssl"
                ? dnsDomains
                    .split(",")
                    .map((domain) => domain.trim().toLowerCase())
                    .filter(Boolean)
                : [];
            if (domains.length) profile.dnsDomains = domains;
            else delete profile.dnsDomains;
            void run({ type: "save_profile", profile })
              .then((ok) => {
                if (ok) saved();
              })
              .finally(() => setSaving(false));
          }
        }}
      >
        <Group>
          {input("name", "name")}
          {/* biome-ignore lint/a11y/noLabelWithoutControl: Select renders a native <select> inside the label */}
          <label className="field">
            <span>{t("type")}</span>
            <Select
              value={value.kind}
              disabled={saving}
              onChange={(event) =>
                set("kind", event.target.value as VpnProfile["kind"])
              }
            >
              <option value="ipsec">{t("ipsec")}</option>
              <option value="ssl">{t("ssl")}</option>
            </Select>
          </label>
          {input("gateway", "gateway", "vpn.example.com")}
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
          {input("username", "username")}
          {value.kind === "ssl" && (
            <>
              {input("certificate", "certificate")}
              <p className="hint">{t("certificateHint")}</p>
            </>
          )}
          <label className="field">
            <span>{t("networks")}</span>
            <input
              value={networks}
              disabled={saving}
              placeholder="10.20.0.0/24"
              onChange={(event) => setNetworks(event.target.value)}
            />
          </label>
          <p className="hint">
            {t(value.kind === "ssl" ? "networksHintSsl" : "networksHint")}
          </p>
          {value.kind === "ssl" && (
            <>
              <label className="field">
                <span>{t("dnsDomains")}</span>
                <input
                  value={dnsDomains}
                  disabled={saving}
                  placeholder="corp.example.com"
                  onChange={(event) => setDnsDomains(event.target.value)}
                  spellCheck={false}
                  autoComplete="off"
                />
              </label>
              <p className="hint">{t("dnsDomainsHint")}</p>
            </>
          )}
        </Group>
        <h2 className="section-title">{t("tunnelTest")}</h2>
        <Group>
          {input("probeHost", "probeHost", "10.20.0.15")}
          <p className="hint">{t("probeHostHint")}</p>
          {/* biome-ignore lint/a11y/noLabelWithoutControl: Select renders a native <select> inside the label */}
          <label className="field">
            <span>{t("method")}</span>
            <Select
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
            </Select>
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
            <div className="spread">
              <h2 className="section-title">{t("secrets")}</h2>
              <button type="button" onClick={secrets} disabled={saving}>
                {t(
                  vpn.hasPassword || (value.kind === "ipsec" && vpn.hasPsk)
                    ? "change"
                    : "provide",
                )}
              </button>
            </div>
            <Group>
              {value.kind === "ipsec" && (
                <Row
                  label={t("psk")}
                  hint={t(vpn.hasPsk ? "stored" : "notStored")}
                />
              )}
              <Row
                label={t("password")}
                hint={t(vpn.hasPassword ? "stored" : "notStored")}
              />
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
        <Dialog
          title={t("discardTitle")}
          close={() => setDiscard(undefined)}
          t={t}
        >
          <p>{t("discardHint")}</p>
          <div className="actions end">
            <button type="button" onClick={() => setDiscard(undefined)}>
              {t("keepEditing")}
            </button>
            <button type="button" className="danger" onClick={discard}>
              {t("discard")}
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
