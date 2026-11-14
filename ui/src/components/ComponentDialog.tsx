import { useState } from "react";
import type { Snapshot } from "../model";
import type { Run } from "../navigation";
import { Dialog, Notice, type T } from "./common";

export function ComponentStatus({ snapshot, t }: { snapshot: Snapshot; t: T }) {
  const state = snapshot.componentOperation;
  if (!state) return null;
  return (
    <Notice tone="warn">
      <p role="status">
        {t(
          state === "settling"
            ? "componentSettling"
            : state === "installing"
              ? "componentInstallPending"
              : "componentRemovePending",
        )}
      </p>
    </Notice>
  );
}

export function ComponentDialog({
  kind,
  run,
  close,
  installed,
  t,
}: {
  kind: "install" | "remove";
  run: Run;
  close: () => void;
  installed: () => void;
  t: T;
}) {
  const [pending, setPending] = useState(false);
  const install = kind === "install";
  return (
    <Dialog
      title={t(install ? "componentInstallTitle" : "componentRemoveTitle")}
      close={close}
      busy={pending}
      t={t}
    >
      <p role="status">
        {t(
          pending
            ? install
              ? "componentInstallPending"
              : "componentRemovePending"
            : install
              ? "componentInstallHint"
              : "componentRemoveHint",
        )}
      </p>
      <div className="actions end">
        <button type="button" onClick={close} disabled={pending}>
          {t("cancel")}
        </button>
        <button
          type="button"
          className={install ? "primary" : "danger-fill"}
          disabled={pending}
          onClick={() => {
            setPending(true);
            void run({
              type: install ? "install_helper" : "remove_helper",
            }).then((ok) => {
              if (ok && install) installed();
              else close();
            });
          }}
        >
          {t(install ? "install" : "remove")}
        </button>
      </div>
    </Dialog>
  );
}
