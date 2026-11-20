import { useId, useLayoutEffect, useRef, useState } from "react";
import {
  BridgeError,
  inspectOvpn,
  listCertificates,
  readOvpnFile,
  validCertificateId,
} from "../bridge";
import {
  Dialog,
  Group,
  Header,
  Notice,
  Row,
  Select,
  type T,
} from "../components/common";
import type {
  Command,
  TokenCertificate,
  VpnKind,
  Profile as VpnProfile,
  VpnView,
} from "../model";
import {
  type Navigate,
  type ProfileOrigin,
  profileOriginRoute,
  type RegisterNavigationGuard,
  type Run,
} from "../navigation";
import { isLinuxPlatform } from "../platform";
import { blankOvpn, blankProfile } from "../profileDefaults";
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
  kind?: VpnKind;
  origin?: ProfileOrigin;
  navigate: Navigate;
  registerNavigationGuard: RegisterNavigationGuard;
  saved: () => void;
  run: Run;
  t: T;
  secrets: () => void;
  remove: () => void;
}) {
  const linux = isLinuxPlatform();
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
  const fileInput = useRef<HTMLInputElement>(null);
  // Retain only the browser's file handle. Read the text at each bridge request.
  const [importedFile, setImportedFile] = useState<File>();
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<{
    key: Parameters<T>[0];
    directive?: string;
  }>();
  const [certificates, setCertificates] = useState<TokenCertificate[]>();
  const [certificateError, setCertificateError] = useState<Parameters<T>[0]>();
  const [listing, setListing] = useState(false);
  const isOvpn = value.kind === "ovpn";
  const ovpn = value.ovpn ?? blankOvpn();
  const moduleValid = validModule(ovpn.module);
  // Open Advanced once when the module still needs to be entered; after that
  // the person controls it, so completing a valid path does not hide the field.
  const [advancedOpen, setAdvancedOpen] = useState(!moduleValid);
  const requiresImport = !vpn || initial.kind !== "ovpn";
  const domains =
    value.kind === "ssl" || isOvpn
      ? dnsDomains
          .split(",")
          .map((domain) => domain.trim().toLowerCase())
          .filter(Boolean)
      : [];
  const importFile = async (file: File) => {
    setImporting(true);
    setImportError(undefined);
    try {
      const info = await inspectOvpn(file);
      setValue((profile) => ({
        ...profile,
        name: profile.name.trim() ? profile.name : (info.name ?? ""),
        gateway: info.gateway,
        port: info.port,
      }));
      setImportedFile(file);
    } catch (error) {
      setImportError(importMessage(error));
    } finally {
      setImporting(false);
    }
  };
  const loadCertificates = async () => {
    if (!moduleValid) return;
    setListing(true);
    setCertificateError(undefined);
    setCertificates(undefined);
    try {
      const list = await listCertificates(ovpn.module);
      setCertificates(list);
      if (!list.some(({ id }) => id === ovpn.certificateId)) {
        setValue((profile) => ({
          ...profile,
          ovpn: { ...ovpn, certificateId: "" },
        }));
      }
    } catch (error) {
      setCertificateError(
        error instanceof Error && error.message === "invalid_module"
          ? "ovpnInvalidModule"
          : error instanceof Error && error.message === "untrusted_module"
            ? "ovpnUntrustedModule"
            : "ovpnTokenUnavailable",
      );
    } finally {
      setListing(false);
    }
  };
  const dirty =
    (isOvpn && !!importedFile) ||
    JSON.stringify(value) !== JSON.stringify(initial) ||
    networks !== initial.networks.join(", ") ||
    dnsDomains !== (initial.dnsDomains ?? []).join(", ");
  const set = <K extends keyof VpnProfile>(key: K, next: VpnProfile[K]) =>
    setValue((profile) => ({ ...profile, [key]: next }));
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
  // OVPN has no username: a value typed under another kind is hidden and not
  // sent, so it must not keep the form from saving.
  const usernameError = !isOvpn && hasShellExpression(value.username);
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
    (!isOvpn ||
      ((!requiresImport || !!importedFile) &&
        moduleValid &&
        validCertificateId(ovpn.certificateId) &&
        validProbeHost(value.probeHost) &&
        Number.isInteger(value.probePort) &&
        domains.length <= 8 &&
        new Set(domains).size === domains.length &&
        domains.every(validDnsName))) &&
    !importing &&
    !listing &&
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
          if (!canSave) return;
          setSaving(true);
          const profile: VpnProfile = {
            ...value,
            networks: isOvpn
              ? []
              : networks
                  .split(",")
                  .map((network) => network.trim())
                  .filter(Boolean),
          };
          if (isOvpn) {
            profile.ovpn = ovpn;
            profile.username = "";
            profile.certificate = "";
          } else {
            delete profile.ovpn;
          }
          if (domains.length) profile.dnsDomains = domains;
          else delete profile.dnsDomains;
          void (async () => {
            const command: Extract<Command, { type: "save_profile" }> = {
              type: "save_profile",
              profile,
            };
            if (isOvpn && importedFile) {
              try {
                command.ovpn_config = await readOvpnFile(importedFile);
              } catch (error) {
                setImportError(importMessage(error));
                return;
              }
            }
            if (await run(command)) saved();
          })().finally(() => setSaving(false));
        }}
      >
        <Group>
          {input("name", "name")}
          {/* biome-ignore lint/a11y/noLabelWithoutControl: Select renders a native <select> inside the label */}
          <label className="field">
            <span>{t("type")}</span>
            <Select
              value={value.kind}
              disabled={saving || importing || listing}
              onChange={(event) => {
                const kind = event.target.value as VpnKind;
                setValue((profile) => ({
                  ...profile,
                  kind,
                  ...(kind === "ovpn" && !profile.ovpn
                    ? { ovpn: blankOvpn() }
                    : {}),
                }));
              }}
            >
              <option value="ipsec">{t("ipsec")}</option>
              <option value="ssl">{t("ssl")}</option>
              <option value="ovpn">{t("ovpn")}</option>
            </Select>
          </label>
          {isOvpn ? (
            <>
              <input
                ref={fileInput}
                type="file"
                hidden
                accept=".ovpn"
                aria-label={t("ovpnConfiguration")}
                onChange={(event) => {
                  const file = event.currentTarget.files?.[0];
                  event.currentTarget.value = "";
                  if (file) void importFile(file);
                }}
              />
              <Row
                label={t("ovpnConfiguration")}
                hint={importedFile ? t("ovpnImported") : undefined}
              >
                <button
                  type="button"
                  disabled={saving || importing}
                  onClick={() => fileInput.current?.click()}
                >
                  {t(importing ? "loading" : "ovpnImport")}
                </button>
              </Row>
              {importError && (
                <Notice tone="error">
                  <p role="alert">
                    {t(importError.key, {
                      directive: importError.directive ?? "",
                    })}
                  </p>
                </Notice>
              )}
              {!!value.gateway && (
                <Row label={t("gateway")} hint={value.gateway} />
              )}
              {!!value.gateway && (
                <Row label={t("port")} hint={String(value.port)} />
              )}
            </>
          ) : (
            <>
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
            </>
          )}
          {(value.kind === "ssl" || isOvpn) && (
            <>
              <label className="field">
                <span>{t("dnsDomains")}</span>
                <input
                  value={dnsDomains}
                  disabled={saving}
                  placeholder={isOvpn ? "corp.example" : "corp.example.com"}
                  onChange={(event) => setDnsDomains(event.target.value)}
                  spellCheck={false}
                  autoComplete="off"
                />
              </label>
              <p className="hint">{t("dnsDomainsHint")}</p>
            </>
          )}
        </Group>
        {isOvpn && (
          <>
            <div className="spread">
              <h2 className="section-title">{t("ovpnCertificates")}</h2>
              <button
                type="button"
                disabled={saving || listing || !moduleValid}
                onClick={() => void loadCertificates()}
              >
                {t(
                  listing
                    ? "loading"
                    : certificateError || certificates?.length === 0
                      ? "tryAgain"
                      : "ovpnListCertificates",
                )}
              </button>
            </div>
            {certificateError && (
              <Notice tone="error">
                <p role="alert">{t(certificateError)}</p>
              </Notice>
            )}
            {certificates?.length === 0 && (
              <p className="hint" role="status">
                {t("ovpnNoCertificates")}
              </p>
            )}
            {!!certificates?.length && (
              <Group>
                {certificates.map((certificate) => (
                  <Row
                    key={certificate.id}
                    label={certificate.subject || certificate.id}
                    hint={t("ovpnCertDetails", {
                      issuer: certificate.issuer || t("ovpnCertMissing"),
                      start:
                        certificate.notBefore?.slice(0, 10) ||
                        t("ovpnCertMissing"),
                      end:
                        certificate.notAfter?.slice(0, 10) ||
                        t("ovpnCertMissing"),
                    })}
                  >
                    <input
                      type="radio"
                      name="ovpn-certificate"
                      aria-label={
                        certificate.subject
                          ? `${certificate.subject} (${certificate.id})`
                          : certificate.id
                      }
                      disabled={saving}
                      checked={certificate.id === ovpn.certificateId}
                      onChange={() =>
                        set("ovpn", { ...ovpn, certificateId: certificate.id })
                      }
                    />
                  </Row>
                ))}
              </Group>
            )}
            <details
              open={advancedOpen}
              onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}
            >
              <summary>{t("ovpnAdvanced")}</summary>
              <Group>
                <label className="field">
                  <span>{t("ovpnModule")}</span>
                  <input
                    value={ovpn.module}
                    disabled={saving || listing}
                    aria-invalid={!moduleValid}
                    placeholder="/usr/lib/libpkcs11-module.so"
                    onChange={(event) => {
                      set("ovpn", {
                        ...ovpn,
                        module: event.target.value,
                        certificateId: "",
                      });
                      setCertificates(undefined);
                      setCertificateError(undefined);
                    }}
                    spellCheck={false}
                    autoComplete="off"
                  />
                </label>
                {!moduleValid && (
                  <p className="hint" role="alert">
                    {t("ovpnInvalidModule")}
                  </p>
                )}
                {/* biome-ignore lint/a11y/noLabelWithoutControl: Select contains its native labeled control. */}
                <label className="field">
                  <span>{t("ovpnTls")}</span>
                  <Select
                    value={ovpn.tls}
                    disabled={saving || listing}
                    onChange={(event) =>
                      set("ovpn", {
                        ...ovpn,
                        tls:
                          event.target.value === "any" ? "any" : "pkcs1_only",
                      })
                    }
                  >
                    <option value="pkcs1_only">{t("ovpnTlsPkcs1")}</option>
                    <option value="any">{t("ovpnTlsAny")}</option>
                  </Select>
                </label>
                <p className="hint">{t("ovpnTlsHint")}</p>
              </Group>
            </details>
          </>
        )}
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
        {!!vpn && !isOvpn && vpn.profile.kind !== "ovpn" && (
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
        {/* Only macOS asks for an administrator password; Linux writes the
            profile as the logged-in user. Linux is silent while idle and
            shows the plain pending text only while saving. */}
        {(!linux || saving) && (
          <p className="hint" role="status">
            {t(
              linux
                ? "savePending"
                : saving
                  ? "adminPending"
                  : "saveRequiresAdmin",
            )}
          </p>
        )}
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

function importMessage(error: unknown): {
  key: Parameters<T>[0];
  directive?: string;
} {
  if (!(error instanceof BridgeError) || error.message !== "invalid_ovpn") {
    return { key: "ovpnImportError" };
  }
  switch (error.detail) {
    case "too_large":
      return { key: "ovpnTooLarge" };
    case "not_utf8":
      return { key: "ovpnNotUtf8" };
    case "malformed":
      return { key: "ovpnMalformed" };
    case "no_remote":
      return { key: "ovpnNoRemote" };
    case "missing_ca":
      return { key: "ovpnMissingCa" };
    default:
      return error.detail &&
        (/^[a-z0-9_-]+$/i.test(error.detail) || error.detail === "setenv opt")
        ? { key: "ovpnForbidden", directive: error.detail }
        : { key: "ovpnImportError" };
  }
}

function validModule(module: string): boolean {
  return (
    module.startsWith("/") &&
    (module.endsWith(".so") || module.endsWith(".dylib")) &&
    new TextEncoder().encode(module).length <= 4096 &&
    !/\p{Cc}/u.test(module) &&
    !module.split("/").includes("..")
  );
}

function validDnsName(host: string): boolean {
  return (
    host.length <= 253 &&
    host
      .split(".")
      .every(
        (label) =>
          label.length <= 63 &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label),
      )
  );
}

function validProbeHost(host: string): boolean {
  if (validDnsName(host)) return true;
  if (!host.includes(":") || !/^[0-9a-f:.]+$/i.test(host)) return false;
  try {
    return new URL(`http://[${host}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
}
