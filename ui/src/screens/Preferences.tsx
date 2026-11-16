import { InstallButton } from "../components/ComponentDialog";
import {
  Group,
  Header,
  Help,
  Icon,
  Row,
  Select,
  type T,
  Toggle,
} from "../components/common";
import type { NativePreferences, Snapshot } from "../model";
import type { Navigate } from "../navigation";
import type { Settings } from "../settings";

export function Preferences({
  snapshot,
  settings,
  update,
  navigate,
  removeComponent,
  install,
  installPending,
  installBusy,
  installBlocked,
  updating,
  installFailed,
  t,
}: {
  snapshot: Snapshot;
  settings: Settings & { preferencesPending: boolean };
  update: (settings: Settings) => void;
  navigate: Navigate;
  removeComponent: () => void;
  install: () => void;
  installPending: boolean;
  installBusy: boolean;
  installBlocked: boolean;
  updating: boolean;
  installFailed: boolean;
  t: T;
}) {
  const pending = settings.preferencesPending;
  const installed = snapshot.helper === "installed" && !installPending;
  const set = <K extends keyof Settings>(key: K, value: Settings[K]) =>
    update({ ...settings, [key]: value });
  return (
    <>
      <Header
        title={t("preferences")}
        back={() => navigate({ page: "panel" })}
        t={t}
      />
      <h2 className="section-title">{t("general")}</h2>
      <Group>
        <Row label={t("startAtLogin")}>
          <Toggle
            label={t("startAtLogin")}
            checked={settings.startup}
            busy={pending}
            onChange={(value) => set("startup", value)}
          />
        </Row>
        <Row label={t("language")}>
          <Select
            aria-label={t("language")}
            value={settings.locale}
            onChange={(event) =>
              set("locale", event.target.value as Settings["locale"])
            }
          >
            <option value="system">{t("system")}</option>
            <option value="pt-BR">Português (Brasil)</option>
            <option value="en-US">English (US)</option>
          </Select>
        </Row>
        <Row label={t("theme")}>
          <Select
            aria-label={t("theme")}
            value={settings.theme}
            onChange={(event) =>
              set("theme", event.target.value as Settings["theme"])
            }
          >
            <option value="system">{t("system")}</option>
            <option value="light">{t("light")}</option>
            <option value="dark">{t("dark")}</option>
          </Select>
        </Row>
      </Group>
      <h2 className="section-title">{t("tunnelTest")}</h2>
      <Group>
        <Row label={t("testEvery")} help={t("testEveryHelp")}>
          <Select
            aria-label={t("testEvery")}
            value={settings.interval}
            busy={pending}
            onChange={(event) =>
              set(
                "interval",
                Number(event.target.value) as NativePreferences["interval"],
              )
            }
          >
            {[10, 30, 60].map((count) => (
              <option key={count} value={count}>
                {t("seconds", { count })}
              </option>
            ))}
          </Select>
        </Row>
        <Row label={t("notifyStale")} help={t("notifyStaleHelp")}>
          <Toggle
            label={t("notifyStale")}
            checked={settings.notify}
            busy={pending}
            onChange={(value) => set("notify", value)}
          />
        </Row>
        <Row
          label={t("autoReconnect")}
          hint={t("afterThree")}
          help={t("autoReconnectHelp")}
        >
          <Toggle
            label={t("autoReconnect")}
            checked={settings.reconnect}
            busy={pending}
            onChange={(value) => set("reconnect", value)}
          />
        </Row>
      </Group>
      <h2 className="section-title">{t("vpns")}</h2>
      <Group>
        {snapshot.vpns.map((vpn) => (
          <button
            type="button"
            className="profile-row"
            key={vpn.profile.id}
            onClick={() =>
              navigate({
                page: "profile",
                id: vpn.profile.id,
                origin: "preferences",
              })
            }
          >
            <span>
              {vpn.profile.name}
              <small>{t(vpn.profile.kind)}</small>
            </span>
            <Icon name="chevron" />
          </button>
        ))}
        <button
          type="button"
          className="link add-profile"
          onClick={() => navigate({ page: "new", origin: "preferences" })}
        >
          <Icon name="plus" />
          {t("addVpn")}
        </button>
      </Group>
      <h2 className="section-title">{t("administrator")}</h2>
      <Group>
        <div className="setting-row component-row">
          <span className="setting-label component-title">
            {t(
              installed
                ? "helperInstalled"
                : updating
                  ? "helperOutdated"
                  : "helperMissing",
            )}
            <Help text={t("componentHelp")} />
          </span>
          {installed ? (
            <>
              <small className="component-version">{snapshot.version}</small>
              <button
                type="button"
                className="icon-button component-remove"
                aria-label={t("remove")}
                title={t("remove")}
                disabled={!!snapshot.componentOperation}
                onClick={removeComponent}
              >
                <Icon name="trash" />
              </button>
            </>
          ) : (
            <InstallButton
              className="primary component-install"
              install={install}
              pending={installPending}
              disabled={installBusy || installBlocked}
              updating={updating}
              failed={installFailed}
              t={t}
            />
          )}
          <small className="component-hint">
            {t(
              installBlocked && !installed
                ? updating
                  ? "componentUpdateBlocked"
                  : "componentInstallBlocked"
                : installed
                  ? "installedHint"
                  : "helperHint",
            )}
          </small>
        </div>
      </Group>
    </>
  );
}
