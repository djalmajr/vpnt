#!/usr/bin/env python3
"""Named mutants for the permanent utun handoff fixture.

The checker extracts the pinned original strongSwan archive, applies the
canonical patch and passes the patched TU here. Each mutant is a private copy of
that TU, compiled/linked against the same fixture objects; the canonical TU is
never edited. A kill is the named test's controlled assertion (exit 1 with the
expected message), never a compile/link error or a timeout.
"""
import hashlib
import subprocess
from pathlib import Path

# One focused mechanism per mutant; copied from the fixed sender candidate.
MUTATIONS = [
    ("opt-in-ignored", "default_off_leaves_channel_untouched",
     [("\tif (retain_utun && !vpnt_channel_prepare())\n",
       "\tretain_utun = TRUE;\n\tif (retain_utun && !vpnt_channel_prepare())\n")],
     "(flags & FD_CLOEXEC) == 0"),
    ("send-before-up", "enabled_sends_after_up_once",
     [("\tif (!this->tun->set_mtu(this->tun, TUN_DEFAULT_MTU) ||\n",
       "\tif (retain_utun)\n\t{\n\t\t(void)vpnt_send_utun(this->tun->get_fd(this->tun));\n\t}\n"
       "\tif (!this->tun->set_mtu(this->tun, TUN_DEFAULT_MTU) ||\n")],
     "g_up_saw_datagram == 0"),
    ("two-descriptors", "enabled_sends_after_up_once",
     [("char control[CMSG_SPACE(sizeof(int))];",
       "char control[CMSG_SPACE(2 * sizeof(int))];"),
      ("\tcmsg->cmsg_len = CMSG_LEN(sizeof(int));\n"
       "\tmemcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));\n",
       "\tcmsg->cmsg_len = CMSG_LEN(2 * sizeof(int));\n"
       "\tmemcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));\n"
       "\tmemcpy((char*)CMSG_DATA(cmsg) + sizeof(fd), &fd, sizeof(fd));\n")],
     "fds == 1"),
    ("wrong-payload", "enabled_sends_after_up_once",
     [("{ 0x56, 0x50, 0x55, 0x46, 1, 0, 0, 0 }",
       "{ 0x57, 0x50, 0x55, 0x46, 1, 0, 0, 0 }")],
     "payload[0] == 0x56"),
    ("send-failure-no-cleanup", "peer_closed_send_failure_destroys",
     [("\t\t\tDBG1(DBG_KNL, \"kernel-libipsec channel send failed\");\n"
       "\t\t\tdestroy(this);\n\t\t\treturn NULL;\n",
       "\t\t\tDBG1(DBG_KNL, \"kernel-libipsec channel send failed\");\n")],
     "plugin == NULL"),
    ("channel-not-closed", "enabled_sends_after_up_once",
     [("\t\tclose(VPNT_CHANNEL_FD);\n\t\tif (!sent)\n",
       "\t\tif (!sent)\n")],
     "flags < 0"),
    ("closed-prepare-ignored", "closed_channel_fails_before_publication",
     [("\tif (retain_utun && !vpnt_channel_prepare())\n",
       "\tif (FALSE)\n")],
     "g_destroy_calls == 0"),
    ("invalid-channel-failure-ignored-stream",
     "stream_channel_fails_before_publication",
     [("static bool vpnt_send_utun(int fd)\n{\n",
       "static bool vpnt_send_utun(int fd)\n{\n\treturn TRUE;\n")],
     "plugin == NULL"),
    ("invalid-channel-failure-ignored-non-unix",
     "non_unix_channel_fails_before_publication",
     [("static bool vpnt_send_utun(int fd)\n{\n",
       "static bool vpnt_send_utun(int fd)\n{\n\treturn TRUE;\n")],
     "plugin == NULL"),
    ("mtu-up-failure-ignored-up", "up_failure_sends_nothing",
     [("\tif (!this->tun->set_mtu(this->tun, TUN_DEFAULT_MTU) ||\n"
       "\t\t!this->tun->up(this->tun))\n\t{\n",
       "\tif (FALSE)\n\t{\n")],
     "plugin == NULL"),
    ("mtu-up-failure-ignored-mtu", "mtu_failure_sends_nothing",
     [("\tif (!this->tun->set_mtu(this->tun, TUN_DEFAULT_MTU) ||\n"
       "\t\t!this->tun->up(this->tun))\n\t{\n",
       "\tif (FALSE)\n\t{\n")],
     "plugin == NULL"),
    ("omit-tun-cloexec", "enabled_sends_after_up_once",
     [("\t/* Prevent the original TUN fd from leaking into a later exec. */\n"
       "\tflags = fcntl(fd, F_GETFD);\n"
       "\tif (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)\n"
       "\t{\n\t\treturn FALSE;\n\t}\n", "")],
     "flags & FD_CLOEXEC"),
    ("pre-init-destroy", "closed_channel_fails_before_publication",
     [("\t\tDBG1(DBG_KNL, \"kernel-libipsec channel preparation failed\");\n"
       "\t\tclose(VPNT_CHANNEL_FD);\n\t\tfree(this);\n",
       "\t\tDBG1(DBG_KNL, \"kernel-libipsec channel preparation failed\");\n"
       "\t\tclose(VPNT_CHANNEL_FD);\n\t\tdestroy(this);\n")],
     "libipsec_deinit before init"),
]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(tu, cflags, fixture_objects, out, timeout=30):
    """Run every mutant in a private directory; return one row per mutant."""
    tu = Path(tu)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    original = tu.read_text()
    baseline = digest(tu)
    rows = []
    for label, test, replacements, expected in MUTATIONS:
        mutated = original
        for before, after in replacements:
            if mutated.count(before) != 1:
                raise RuntimeError(f"{label}: anchor count {mutated.count(before)}")
            mutated = mutated.replace(before, after, 1)
        source = out / f"{label}.c"
        source.write_text(mutated)
        obj = out / f"{label}.o"
        binary = out / f"{label}.fixture"
        compiled = subprocess.run(["cc", *cflags, "-c", str(source), "-o", str(obj)],
                                  capture_output=True, text=True)
        if compiled.returncode != 0:
            raise RuntimeError(f"{label}: compile failed\n{compiled.stdout}{compiled.stderr}")
        linked = subprocess.run(["cc", str(obj), *map(str, fixture_objects), "-o", str(binary)],
                                capture_output=True, text=True)
        if linked.returncode != 0:
            raise RuntimeError(f"{label}: link failed\n{linked.stdout}{linked.stderr}")
        try:
            result = subprocess.run([str(binary), test], capture_output=True, text=True,
                                    timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"{label}: timeout") from error
        log = result.stdout + result.stderr
        (out / f"{label}.log").write_text(log)
        killed = (result.returncode == 1
                  and f"FAIL {test}:" in log
                  and expected in log)
        rows.append({"label": label, "test": test, "exit": result.returncode,
                     "killed": killed, "assertion": expected in log})
        if not killed:
            raise RuntimeError(f"{label}: unexpected outcome\n{log}")
    if digest(tu) != baseline:
        raise RuntimeError("canonical patched TU changed")
    return rows
