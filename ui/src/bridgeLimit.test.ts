import { describe, expect, test } from "bun:test";
import { readOvpnFile } from "./bridge";

describe("OpenVPN file size", () => {
  test("accepts 32 KiB and rejects one byte more", async () => {
    const allowed = new File(["x".repeat(32 * 1024)], "profile.ovpn");
    const oversized = new File(["x".repeat(32 * 1024 + 1)], "profile.ovpn");
    expect((await readOvpnFile(allowed)).length).toBe(32 * 1024);
    await expect(readOvpnFile(oversized)).rejects.toMatchObject({
      message: "invalid_ovpn",
      detail: "too_large",
    });
  });
});
