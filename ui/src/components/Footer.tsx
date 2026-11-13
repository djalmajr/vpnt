import { active, type Snapshot } from "../model";
import type { Navigate, Run } from "../navigation";
import type { T } from "./common";
import { Menu, MenuItem, MenuSeparator } from "./Menu";

export function Footer({
  snapshot,
  navigate,
  run,
  t,
}: {
  snapshot: Snapshot;
  navigate: Navigate;
  run: Run;
  t: T;
}) {
  const anyActive = snapshot.vpns.some((vpn) => active(vpn.state));
  return (
    <footer className="footer">
      <small>{t("version", { version: snapshot.version })}</small>
      <Menu label={t("options")}>
        <MenuItem
          icon="power"
          disabled={!anyActive}
          onSelect={() => void run({ type: "disconnect_all" })}
        >
          {t("disconnectAll")}
        </MenuItem>
        <MenuItem
          icon="refresh"
          disabled={!anyActive}
          onSelect={() => {
            for (const vpn of snapshot.vpns.filter((vpn) => active(vpn.state)))
              void run({ type: "probe", id: vpn.profile.id });
          }}
        >
          {t("testNow")}
        </MenuItem>
        <MenuItem icon="log" onSelect={() => navigate({ page: "log" })}>
          {t("viewLog")}
        </MenuItem>
        <MenuSeparator />
        <MenuItem
          icon="settings"
          onSelect={() => navigate({ page: "preferences" })}
        >
          {t("preferences")}
        </MenuItem>
        <MenuItem icon="info" onSelect={() => navigate({ page: "about" })}>
          {t("about")}
        </MenuItem>
        <MenuSeparator />
        <MenuItem icon="quit" onSelect={() => void run({ type: "quit" })}>
          {t("quit")}
        </MenuItem>
      </Menu>
    </footer>
  );
}
