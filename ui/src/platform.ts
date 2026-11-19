/**
 * The Linux shell marks `<html>` before the UI loads: see
 * `src/desktop_linux/mod.rs`. Tests call this while a DOM is registered;
 * server rendering on macOS has no document at all.
 */
export function isLinuxPlatform(doc?: Document): boolean {
  const root = doc ?? (typeof document === "undefined" ? undefined : document);
  return root?.documentElement.dataset.platform === "linux";
}
