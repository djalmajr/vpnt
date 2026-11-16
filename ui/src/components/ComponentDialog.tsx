import { useState } from "react";
import type { Snapshot } from "../model";
import type { Run } from "../navigation";
import { Dialog, Icon, Notice, type T } from "./common";

export function ComponentStatus({
  snapshot,
  installing,
  t,
}: {
  snapshot: Snapshot;
  installing: boolean;
  t: T;
}) {
  const state = snapshot.componentOperation;
  if (!installing && !state) return null;
  return (
    <Notice tone="warn">
      <p role="status">
        {t(
          installing
            ? "componentInstallPending"
            : state === "settling"
              ? "componentSettling"
              : state === "installing"
                ? "componentInstallPending"
                : "componentRemovePending",
        )}
      </p>
    </Notice>
  );
}

export function InstallButton({
  install,
  pending,
  disabled,
  updating,
  failed,
  className,
  t,
}: {
  install: () => void;
  pending: boolean;
  disabled: boolean;
  updating: boolean;
  failed: boolean;
  className: string;
  t: T;
}) {
  return (
    <button
      type="button"
      className={className}
      disabled={disabled || pending}
      aria-busy={pending || undefined}
      onClick={install}
    >
      {pending && <Icon name="loader" />}
      {t(failed && !pending ? "tryAgain" : updating ? "update" : "install")}
    </button>
  );
}

/* Removal still requires confirmation. Cancel remains unavailable while the
   privileged operation is settling. */
export function ComponentDialogBody({
  pending,
  confirm,
  close,
  t,
}: {
  pending: boolean;
  confirm: () => void;
  close: () => void;
  t: T;
}) {
  return (
    <>
      <p role="status">
        {t(pending ? "componentRemovePending" : "componentRemoveHint")}
      </p>
      <div className="actions end">
        <button type="button" onClick={close} disabled={pending}>
          {t("cancel")}
        </button>
        <button
          type="button"
          className="danger-fill"
          disabled={pending}
          aria-busy={pending || undefined}
          onClick={confirm}
        >
          {pending && <Icon name="loader" />}
          {t("remove")}
        </button>
      </div>
    </>
  );
}

export function ComponentDialog({
  run,
  close,
  t,
}: {
  run: Run;
  close: () => void;
  t: T;
}) {
  const [pending, setPending] = useState(false);
  return (
    <Dialog
      title={t("componentRemoveTitle")}
      close={close}
      busy={pending}
      t={t}
    >
      <ComponentDialogBody
        pending={pending}
        close={close}
        t={t}
        confirm={() => {
          setPending(true);
          void run({ type: "remove_helper" }).then(close);
        }}
      />
    </Dialog>
  );
}
