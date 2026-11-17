import { useState } from "react";
import type { VpnView } from "../model";
import type { Run } from "../navigation";
import { Dialog, Icon, type T } from "./common";

/* Pure body so SSR tests cover the saving paint without a renderer: while
   the profile removal is in flight, the spinner sits inside the danger
   button, before its label, and the wait text carries no spinner. */
export function RemoveDialogBody({
  saving,
  confirm,
  close,
  t,
}: {
  saving: boolean;
  confirm: () => void;
  close: () => void;
  t: T;
}) {
  return (
    <>
      <p role="status">{t(saving ? "adminPending" : "removeHint")}</p>
      <div className="actions end">
        <button type="button" onClick={close} disabled={saving}>
          {t("cancel")}
        </button>
        <button
          type="button"
          className="danger-fill"
          disabled={saving}
          aria-busy={saving || undefined}
          onClick={confirm}
        >
          {saving && <Icon name="loader" />}
          {t("remove")}
        </button>
      </div>
    </>
  );
}

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
      <RemoveDialogBody
        saving={saving}
        close={close}
        t={t}
        confirm={() => {
          setSaving(true);
          void run({ type: "remove_profile", id: vpn.profile.id })
            .then((ok) => {
              if (ok) removed();
            })
            .finally(() => setSaving(false));
        }}
      />
    </Dialog>
  );
}
