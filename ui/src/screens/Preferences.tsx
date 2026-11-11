import { Group, Header, Icon, Row, type T, Toggle } from "../components/common";
import type { Snapshot } from "../model";
import type { Navigate, Run } from "../navigation";
import type { Settings } from "../settings";

export function Preferences({
  snapshot,
  settings,
  update,
  navigate,
  run,
  t,
}: {
  snapshot: Snapshot;
  settings: Settings;
  update: (settings: Settings) => void;
  navigate: Navigate;
  run: Run;
  t: T;
}) {
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
            onChange={(value) => set("startup", value)}
          />
        </Row>
        <Row label={t("language")}>
          <select
            aria-label={t("language")}
            value={settings.locale}
            onChange={(event) =>
              set("locale", event.target.value as Settings["locale"])
            }
          >
            <option value="system">{t("system")}</option>
            <option value="pt-BR">Português (Brasil)</option>
            <option value="en-US">English (US)</option>
          </select>
        </Row>
        <Row label={t("theme")}>
          <select
            aria-label={t("theme")}
            value={settings.theme}
            onChange={(event) =>
              set("theme", event.target.value as Settings["theme"])
            }
          >
            <option value="system">{t("system")}</option>
            <option value="light">{t("light")}</option>
            <option value="dark">{t("dark")}</option>
          </select>
        </Row>
      </Group>
      <h2 className="section-title">{t("tunnelTest")}</h2>
      <Group>
        <Row label={t("testEvery")}>
          <select
            aria-label={t("testEvery")}
            value={settings.interval}
            onChange={(event) => set("interval", Number(event.target.value))}
          >
            {[10, 30, 60].map((count) => (
              <option key={count} value={count}>
                {t("seconds", { count })}
              </option>
            ))}
          </select>
        </Row>
        <Row label={t("notifyStale")}>
          <Toggle
            label={t("notifyStale")}
            checked={settings.notify}
            onChange={(value) => set("notify", value)}
          />
        </Row>
        <Row label={t("autoReconnect")} hint={t("afterThree")}>
          <Toggle
            label={t("autoReconnect")}
            checked={settings.reconnect}
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
            onClick={() => navigate({ page: "profile", id: vpn.profile.id })}
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
          onClick={() => navigate({ page: "new" })}
        >
          <Icon name="plus" />
          {t("addVpn")}
        </button>
      </Group>
      <h2 className="section-title">{t("administrator")}</h2>
      <Group>
        <Row
          label={t(
            snapshot.helper === "installed"
              ? "helperInstalled"
              : "helperMissing",
          )}
          hint={t(
            snapshot.helper === "installed" ? "installedHint" : "helperHint",
          )}
        >
          {snapshot.helper === "installed" ? (
            <small>{snapshot.version}</small>
          ) : (
            <button
              type="button"
              className="primary"
              onClick={() => navigate({ page: "onboarding" })}
            >
              {t("install")}
            </button>
          )}
        </Row>
        {snapshot.helper === "installed" && (
          <Row label={t("removeHelper")}>
            <button
              type="button"
              className="danger"
              onClick={() => void run({ type: "remove_helper" })}
            >
              {t("remove")}
            </button>
          </Row>
        )}
      </Group>
    </>
  );
}
