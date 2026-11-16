import { useState } from "react";
import type { Snapshot } from "../model";
import type { Run } from "../navigation";
import { Dialog, Icon, Notice, type T } from "./common";

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

/* Pure body so SSR tests cover the pending paint without a renderer: while
   waiting, the spinner sits inside the primary button, before its label,
   and the wait text carries no spinner. Cancel stays blocked because the
   helper operation itself cannot be cancelled from this dialog. */
export function ComponentDialogBody({
  kind,
  pending,
  confirm,
  close,
  t,
}: {
  kind: "install" | "remove";
  pending: boolean;
  confirm: () => void;
  close: () => void;
  t: T;
}) {
  const install = kind === "install";
  return (
    <>
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
          aria-busy={pending || undefined}
          onClick={confirm}
        >
          {pending && <Icon name="loader" />}
          {t(install ? "install" : "remove")}
        </button>
      </div>
    </>
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
      <ComponentDialogBody
        kind={kind}
        pending={pending}
        close={close}
        t={t}
        confirm={() => {
          setPending(true);
          void run({
            type: install ? "install_helper" : "remove_helper",
          }).then((ok) => {
            if (ok && install) installed();
            else close();
          });
        }}
      />
    </Dialog>
  );
}
