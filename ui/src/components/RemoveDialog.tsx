import { useState } from "react";
import type { VpnView } from "../model";
import type { Run } from "../navigation";
import { Dialog, type T } from "./common";

export function RemoveDialog({
  vpn,
  run,
  close,
  removed,
  t,
}: {
  vpn: VpnView;
  run: Run;
  close: () => void;
  removed: () => void;
  t: T;
}) {
  const [saving, setSaving] = useState(false);
  return (
    <Dialog
      title={t("removeTitle", { name: vpn.profile.name })}
      close={close}
      busy={saving}
      t={t}
    >
      <p role="status">{t(saving ? "adminPending" : "removeHint")}</p>
      <div className="actions end">
        <button type="button" onClick={close} disabled={saving}>
          {t("cancel")}
        </button>
        <button
          type="button"
          className="danger-fill"
          disabled={saving}
          onClick={() => {
            setSaving(true);
            void run({ type: "remove_profile", id: vpn.profile.id })
              .then((ok) => {
                if (ok) removed();
              })
              .finally(() => setSaving(false));
          }}
        >
          {t("remove")}
        </button>
      </div>
    </Dialog>
  );
}
