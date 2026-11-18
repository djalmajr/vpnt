import type {
  Command,
  OvpnInspection,
  Reply,
  Snapshot,
  TokenCertificate,
} from "./model";

declare global {
  interface Window {
    ipc?: { postMessage(body: string): void };
    __vpntReply?: (reply: Reply) => void;
  }
}

const pending = new Map<
  string,
  {
    resolve(reply: Reply): void;
    reject(error: Error): void;
    timer: ReturnType<typeof setTimeout>;
  }
>();
let sequence = 0;
function receiveReply(reply: Reply) {
  const request = pending.get(reply.id);
  if (!request) return;
  clearTimeout(request.timer);
  pending.delete(reply.id);
  request.resolve(reply);
}

export class BridgeError extends Error {
  constructor(
    code: string,
    readonly detail?: string,
  ) {
    super(code);
  }
}

const maxOvpnFileBytes = 32 * 1024;
const maxOvpnRequestBytes = 128 * 1024;

export async function readOvpnFile(file: File): Promise<string> {
  if (file.size > maxOvpnFileBytes) {
    throw new BridgeError("invalid_ovpn", "too_large");
  }
  const bytes = await file.arrayBuffer();
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new BridgeError("invalid_ovpn", "not_utf8");
  }
}

export async function inspectOvpn(file: File): Promise<OvpnInspection> {
  const reply = await request({
    type: "inspect_ovpn",
    content: await readOvpnFile(file),
  });
  const info = reply.ovpn;
  if (
    !info ||
    !(info.name === null || typeof info.name === "string") ||
    typeof info.gateway !== "string" ||
    !Number.isInteger(info.port) ||
    info.port < 1 ||
    info.port > 65535
  )
    throw new Error("invalid_reply");
  return info;
}

export function validCertificateId(id: string): boolean {
  return (
    id.length >= 2 &&
    id.length <= 128 &&
    id.length % 2 === 0 &&
    /^[0-9a-f]+$/.test(id)
  );
}

export async function listCertificates(
  module: string,
): Promise<TokenCertificate[]> {
  const { certificates } = await request({ type: "list_certificates", module });
  if (
    !Array.isArray(certificates) ||
    certificates.some(
      (certificate) =>
        !certificate ||
        typeof certificate.id !== "string" ||
        !validCertificateId(certificate.id) ||
        [
          certificate.subject,
          certificate.issuer,
          certificate.notBefore,
          certificate.notAfter,
        ].some((value) => value !== undefined && typeof value !== "string"),
    )
  )
    throw new Error("invalid_reply");
  return certificates;
}

export async function invoke(command: Command): Promise<Snapshot> {
  const reply = await request(command);
  if (!reply.snapshot) throw new Error("invalid_reply");
  return reply.snapshot;
}

async function request(command: Command): Promise<Reply> {
  const interactive = [
    "toggle",
    "connect",
    "disconnect",
    "reconnect",
    "save_secrets",
    "save_profile",
    "remove_profile",
    "install_helper",
    "remove_helper",
  ].includes(command.type);
  const component =
    command.type === "install_helper" || command.type === "remove_helper";
  const timeout = component ? 610000 : interactive ? 120000 : 10000;
  const id = `ui-${++sequence}`;
  const locale = document.documentElement.lang === "pt-BR" ? "pt-BR" : "en-US";
  const body = JSON.stringify({ id, command, locale });
  if (
    (command.type === "inspect_ovpn" ||
      (command.type === "save_profile" && command.ovpn_config !== undefined)) &&
    new TextEncoder().encode(body).length > maxOvpnRequestBytes
  )
    throw new BridgeError(
      command.type === "save_profile" ? "ovpnTooLarge" : "invalid_ovpn",
      "too_large",
    );
  const ipc = window.ipc;
  const finish = (reply: Reply) => {
    if (reply.id !== id) throw new Error("invalid_reply");
    if (reply.error) throw new BridgeError(reply.error, reply.detail);
    return reply;
  };
  if (!ipc) {
    const response = await fetch("/api/command", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(timeout),
    });
    if (!response.ok) throw new Error("backend_unavailable");
    const reply: Reply = await response.json();
    return finish(reply);
  }
  window.__vpntReply = receiveReply;
  return new Promise<Reply>((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("backend_unavailable"));
    }, timeout);
    pending.set(id, { resolve, reject, timer });
    try {
      ipc.postMessage(body);
    } catch {
      clearTimeout(timer);
      pending.delete(id);
      reject(new Error("backend_unavailable"));
    }
  }).then(finish);
}
