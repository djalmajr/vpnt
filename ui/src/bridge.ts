import type { Command, Reply, Snapshot } from "./model";

declare global {
  interface Window {
    ipc?: { postMessage(body: string): void };
    __vpntReply?: (reply: Reply) => void;
  }
}

const pending = new Map<
  string,
  {
    resolve(snapshot: Snapshot): void;
    reject(error: Error): void;
    timer: ReturnType<typeof setTimeout>;
  }
>();
let sequence = 0;
window.__vpntReply = (reply) => {
  const request = pending.get(reply.id);
  if (!request) return;
  clearTimeout(request.timer);
  pending.delete(reply.id);
  if (reply.error || !reply.snapshot)
    request.reject(new Error(reply.error ?? "invalid_reply"));
  else request.resolve(reply.snapshot);
};

export async function invoke(command: Command): Promise<Snapshot> {
  const id = `ui-${++sequence}`;
  const body = JSON.stringify({ id, command });
  const ipc = window.ipc;
  if (!ipc) {
    const response = await fetch("/api/command", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error("backend_unavailable");
    const reply: Reply = await response.json();
    if (reply.id !== id || reply.error || !reply.snapshot)
      throw new Error(reply.error ?? "invalid_reply");
    return reply.snapshot;
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("backend_unavailable"));
    }, 10000);
    pending.set(id, { resolve, reject, timer });
    try {
      ipc.postMessage(body);
    } catch {
      clearTimeout(timer);
      pending.delete(id);
      reject(new Error("backend_unavailable"));
    }
  });
}
