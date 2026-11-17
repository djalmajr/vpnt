#!/usr/bin/env python3
"""Named mutants for the permanent protected-UDP gate.

The checker extracts the pinned original archive, applies the canonical patch and
passes the patched TU here. Each mutant is a private copy of that TU plus the
fixture; compilation/link errors, timeouts and signals are not kills. The
canonical TU is never edited and no real IPsec policy is installed.
"""
import hashlib
import shutil
import subprocess
from pathlib import Path

MUTATIONS = [
    ("opt-in-ignored", "default_off_preserves_upstream",
     [("	vpnt_protect = lib->settings->get_bool(lib->settings,\n"
       "				\"%s.plugins.socket-default.vpnt_protect_transport\", FALSE,\n"
       "				lib->ns);",
       "	vpnt_protect = TRUE;")],
     "(fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0"),
    ("ifindex-lower-bound-removed", "invalid_index_matrix",
     [("	if (ifindex < 1 || ifindex > 65535)", "	if (ifindex > 65535)")],
     "fixture_open_socket(AF_INET, &port) == -1"),
    ("ifindex-upper-bound-removed", "invalid_index_matrix",
     [("	if (ifindex < 1 || ifindex > 65535)", "	if (ifindex < 1)")],
     "g_boundif_calls == 0"),
    ("omit-fd-cloexec", "protected_ipv4",
     [("	flags = fcntl(skt, F_GETFD);\n"
       "	if (flags < 0 || fcntl(skt, F_SETFD, flags | FD_CLOEXEC) < 0)\n"
       "	{\n		return FALSE;\n	}\n", "")],
     "(fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0"),
    ("omit-boundif", "protected_ipv4",
     [("	index = (unsigned int)ifindex;\n"
       "	if (setsockopt(skt, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,\n"
       "				family == AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF,\n"
       "				&index, sizeof(index)) < 0)\n"
       "	{\n		return FALSE;\n	}\n", "")],
     "g_boundif_calls == 1"),
    ("wrong-boundif-family", "protected_ipv4",
     [("	if (setsockopt(skt, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,\n"
       "				family == AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF,\n"
       "				&index, sizeof(index)) < 0)",
       "	if (setsockopt(skt, IPPROTO_IPV6, IPV6_BOUND_IF,\n"
       "				&index, sizeof(index)) < 0)")],
     "fd >= 0"),
    ("omit-outbound-policy", "outbound_policy_failure",
     [("	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;\n"
       "	if (setsockopt(skt, sol, ipsec_policy, &policy, sizeof(policy)) < 0)\n"
       "	{\n		return FALSE;\n	}\n", "")],
     "fixture_open_socket(AF_INET, &port) == -1"),
    ("omit-inbound-policy", "inbound_policy_failure",
     [("	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;\n"
       "	if (setsockopt(skt, sol, ipsec_policy, &policy, sizeof(policy)) < 0)\n"
       "	{\n		return FALSE;\n	}\n", "")],
     "fixture_open_socket(AF_INET, &port) == -1"),
    ("policy-order-reversed", "protected_ipv4",
     [("	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;\n"
       "	if (setsockopt(skt, sol, ipsec_policy, &policy, sizeof(policy)) < 0)\n"
       "	{\n		return FALSE;\n	}\n"
       "	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;\n"
       "	if (setsockopt(skt, sol, ipsec_policy, &policy, sizeof(policy)) < 0)\n"
       "	{\n		return FALSE;\n	}\n",
       "	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;\n"
       "	if (setsockopt(skt, sol, ipsec_policy, &policy, sizeof(policy)) < 0)\n"
       "	{\n		return FALSE;\n	}\n"
       "	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;\n"
       "	if (setsockopt(skt, sol, ipsec_policy, &policy, sizeof(policy)) < 0)\n"
       "	{\n		return FALSE;\n	}\n")],
     "g_policies[0].dir == IPSEC_DIR_OUTBOUND"),
    ("policy-type-changed", "protected_ipv4",
     [("	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;",
       "	policy.sadb_x_policy_type = IPSEC_POLICY_IPSEC;")],
     "g_policies[0].type == IPSEC_POLICY_BYPASS"),
    ("bypass-retained", "protected_ipv4",
     [("	if (!vpnt_protect &&\n"
       "		!charon->kernel->bypass_socket(charon->kernel, skt, family))\n"
       "#else\n"
       "	if (!charon->kernel->bypass_socket(charon->kernel, skt, family))\n"
       "#endif",
       "	if (!charon->kernel->bypass_socket(charon->kernel, skt, family))\n"
       "#else\n"
       "	if (!charon->kernel->bypass_socket(charon->kernel, skt, family))\n"
       "#endif")],
     "g_bypass_calls == 0"),
    ("boundif-failure-continues", "boundif_failure",
     [("	if (setsockopt(skt, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,\n"
       "				family == AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF,\n"
       "				&index, sizeof(index)) < 0)\n"
       "	{\n		return FALSE;\n	}\n",
       "	if (setsockopt(skt, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,\n"
       "				family == AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF,\n"
       "				&index, sizeof(index)) < 0)\n"
       "	{\n	}\n")],
     "fixture_open_socket(AF_INET, &port) == -1"),
]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(tu, cflags, fixtures, out, timeout=30):
    """Run all mutants in private directories; return one row per mutant."""
    tu = Path(tu)
    fixtures = Path(fixtures)
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
        directory = out / label
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
        for name in ["protected_udp.h", "protected_udp.c", "protected_udp_tests.c"]:
            shutil.copy2(fixtures / name, directory / name)
        (directory / "socket_default_socket.c").write_text(mutated)
        objects = []
        for name in ["protected_udp.c", "protected_udp_tests.c"]:
            obj = directory / (Path(name).stem + ".o")
            compiled = subprocess.run(["cc", *cflags, "-c", str(directory / name),
                                       "-o", str(obj)],
                                      capture_output=True, text=True)
            if compiled.returncode != 0:
                raise RuntimeError(f"{label}: compile {name} failed\n"
                                   f"{compiled.stdout}{compiled.stderr}")
            objects.append(obj)
        binary = directory / "fixture"
        linked = subprocess.run(["cc", *map(str, objects), "-Wl,-dead_strip",
                                 "-o", str(binary)],
                                capture_output=True, text=True)
        if linked.returncode != 0:
            raise RuntimeError(f"{label}: link failed\n{linked.stdout}{linked.stderr}")
        try:
            result = subprocess.run([str(binary), test], capture_output=True,
                                    text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"{label}: timeout") from error
        log = result.stdout + result.stderr
        (directory / "mutant.log").write_text(log)
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
