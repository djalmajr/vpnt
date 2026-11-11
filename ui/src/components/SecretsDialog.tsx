import { useState } from "react";
import type { VpnView } from "../model";
import type { Run } from "../navigation";
import { Dialog, type T } from "./common";

export function SecretsDialog({
  vpn,
  connect,
  run,
  close,
  t,
}: {
  vpn: VpnView;
  connect: boolean;
  run: Run;
  close: () => void;
  t: T;
}) {
  const [password, setPassword] = useState("");
  const [psk, setPsk] = useState("");
  const [saving, setSaving] = useState(false);
  const ipsec = vpn.profile.kind === "ipsec";
  return (
    <Dialog
      title={t("secretsTitle", { name: vpn.profile.name })}
      close={close}
      t={t}
    >
      <p>{t("secretsHint")}</p>
      <form
        className="secret-form"
        onSubmit={(event) => {
          event.preventDefault();
          setSaving(true);
          void run({ type: "save_secrets", id: vpn.profile.id, password, psk })
            .then(async (ok) => {
              if (ok) {
                setPassword("");
                setPsk("");
                if (connect) await run({ type: "toggle", id: vpn.profile.id });
                close();
              }
            })
            .finally(() => setSaving(false));
        }}
      >
        <input
          type="hidden"
          name="username"
          value={vpn.profile.username}
          autoComplete="username"
        />
        {ipsec && (
          <label className="field">
            <span>{t("psk")}</span>
            <input
              type="password"
              required
              value={psk}
              maxLength={4096}
              onChange={(event) => setPsk(event.target.value)}
              autoComplete="new-password"
            />
          </label>
        )}
        <label className="field">
          <span>{t("password")}</span>
          <input
            type="password"
            required
            value={password}
            maxLength={4096}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="new-password"
          />
        </label>
        <div className="actions end">
          <button type="button" onClick={close}>
            {t("cancel")}
          </button>
          <button
            type="submit"
            className="primary"
            disabled={saving || !password || (ipsec && !psk)}
          >
            {t(connect ? "storeConnect" : "store")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
