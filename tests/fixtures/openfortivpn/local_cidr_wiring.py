#!/usr/bin/env python3
"""Behavioural oracle for the VPT-29 Fortinet local-scope wiring.

It runs the real openfortivpn binary against a loopback TLS gateway and a fake
pppd, and asserts what reaches the pppd side of the pty. Nothing leaves the
machine: no real pppd, no network beyond 127.0.0.1, no profile, no service.

usage: local_cidr_wiring.py <openfortivpn> <work-dir> <cert.pem> <key.pem>
                            <sha256-pin> <scope> [as-root-argv...]
       local_cidr_wiring.py --print-fake-pppd

The binary must have been built with PPP_PATH=<work-dir>/fake-pppd (the check
script rebuilds a private copy of the prepared tree that way). Each case gets
its own directory under <work-dir>; the fake pppd writes `argv` (NUL separated)
and `frames.log` (one hex PPP frame per line, HDLC removed) there.

Exit status: 0 every case behaved, 1 one did not, 2 the fixture cannot run.
"""

import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

HOLD = 4.0  # longest wait for one frame to reach the pty, in seconds
REFUSED_HOLD = 2.0  # how long a refused frame may still be forwarded, in seconds

# Gateway-to-client PPP frames, starting at the PPP Protocol field.
LCP_A = bytes.fromhex("c021 01 01 0004")
LCP_B = bytes.fromhex("c021 01 02 0004")
IPCP_ACK = "8021 02 {id:02x} 000a 0306 {addr}"
IPCP_IN = bytes.fromhex(IPCP_ACK.format(id=7, addr="0a630002"))  # 10.99.0.2
IPCP_OUT = bytes.fromhex(IPCP_ACK.format(id=8, addr="c000024d"))  # 192.0.2.77
IPCP_NEIGHBOUR = bytes.fromhex(IPCP_ACK.format(id=9, addr="0a630102"))  # 10.99.1.2
CCP_DEFLATE = bytes.fromhex("80fd 01 09 0008 1a04 7800")
CCP_LINK = bytes.fromhex("80fb 01 0a 0004")
COMPRESSED = bytes.fromhex("00fd 0001 8021 0207 000a 0306 c000024d")
COMPRESSED_PFC = bytes.fromhex("fd 0001 8021 0207 000a 0306 c000024d")
MULTILINK = bytes.fromhex("003d c000 0001 8021 0207 000a 0306 c000024d")

# (label, frames the gateway sends, frames pppd must read, the client must be
# denied). A frame the client refuses ends the attempt: nothing after it counts.
CASES = [
    ("IPCP local inside the scope reaches the pty",
     [LCP_A, IPCP_IN, LCP_B], [LCP_A, IPCP_IN, LCP_B], False),
    ("IPCP local outside the scope ends the attempt before the pty",
     [LCP_A, IPCP_OUT], [LCP_A], True),
    ("IPCP local in a neighbour /24 ends the attempt before the pty",
     [LCP_A, IPCP_NEIGHBOUR], [LCP_A], True),
    ("CCP offered by the gateway never reaches the pty",
     [LCP_A, CCP_DEFLATE], [LCP_A], True),
    ("individual-link CCP never reaches the pty",
     [LCP_A, CCP_LINK], [LCP_A], True),
    ("a compressed datagram never reaches the pty",
     [LCP_A, COMPRESSED], [LCP_A], True),
    ("a compressed datagram with a compressed protocol field never reaches the pty",
     [LCP_A, COMPRESSED_PFC], [LCP_A], True),
    ("a multilink fragment never reaches the pty",
     [LCP_A, MULTILINK], [LCP_A], True),
]

# Options pppd must receive: compression off, so the kernel never decompresses.
REQUIRED_ARGV = ["noccp", "nobsdcomp", "nodeflate", "nopredictor1"]
DENIED_EXIT = 3  # VPNT_IPCP_DENIED_EXIT


def fake_pppd():
    return """#!/usr/bin/env python3
import os, signal, sys, termios, tty

def stop(signum, frame):
    sys.exit(0)

signal.signal(signal.SIGTERM, stop)
directory = os.environ["VPNT_FAKE_PPPD_DIR"]
with open(os.path.join(directory, "argv"), "wb") as out:
    out.write(b"".join(a.encode() + b"\\0" for a in sys.argv[1:]))
tty.setraw(0, termios.TCSANOW)
log = os.open(os.path.join(directory, "frames.log"),
              os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)

def emit(raw):
    frame, escaped = bytearray(), False
    for byte in raw:
        if escaped:
            frame.append(byte ^ 0x20)
            escaped = False
        elif byte == 0x7d:
            escaped = True
        else:
            frame.append(byte)
    if frame[:2] == b"\\xff\\x03":
        frame = frame[2:]
    if len(frame) > 2:
        os.write(log, bytes(frame[:-2]).hex().encode() + b"\\n")

def fcs16(data):
    fcs = 0xffff
    for byte in data:
        fcs ^= byte
        for _ in range(8):
            fcs = (fcs >> 1) ^ 0x8408 if fcs & 1 else fcs >> 1
    return fcs ^ 0xffff

# The client lets nothing through to pppd until pppd has spoken first, as a
# real pppd does with its LCP Configure-Request.
hello = bytes.fromhex("ff03 c021 01 01 0004")
hello += fcs16(hello).to_bytes(2, "little")
wire = bytearray(b"\x7e")
for byte in hello:
    wire += bytes([0x7d, byte ^ 0x20]) if byte < 0x20 or byte in (0x7d, 0x7e) else bytes([byte])
os.write(1, bytes(wire) + b"\x7e")

pending = bytearray()
while True:
    try:
        data = os.read(0, 4096)
    except OSError:
        break
    if not data:
        break
    for byte in data:
        if byte == 0x7e:
            if pending:
                emit(pending)
            pending = bytearray()
        else:
            pending.append(byte)
"""


def delivered(directory):
    try:
        with open(os.path.join(directory, "frames.log")) as log:
            return [line.strip() for line in log if line.strip()]
    except FileNotFoundError:
        return []


class Gateway(threading.Thread):
    """A loopback TLS gateway that logs the client in and then sends frames."""

    def __init__(self, cert, key, directory, frames, expected):
        super().__init__(daemon=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.context = context
        self.directory = directory
        self.frames = frames
        self.expected = expected
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stopping = False
        self.notes = []
        self.tunnel_requests = 0

    def run(self):
        while not self.stopping:
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def stop(self):
        self.stopping = True
        self.listener.close()

    @staticmethod
    def respond(conn, body=b"", headers=""):
        conn.sendall(("HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n"
                      % (headers, len(body))).encode() + body)

    def serve(self, raw):
        try:
            conn = self.context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        try:
            buffer = b""
            while True:
                while b"\r\n\r\n" not in buffer:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buffer += chunk
                head, _, buffer = buffer.partition(b"\r\n\r\n")
                lines = head.decode("latin-1").split("\r\n")
                method, path = lines[0].split(" ")[:2]
                length = 0
                for line in lines[1:]:
                    if line.lower().startswith("content-length:"):
                        length = int(line.split(":", 1)[1])
                while len(buffer) < length:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buffer += chunk
                buffer = buffer[length:]
                if path == "/remote/logincheck":
                    self.respond(conn, b"ret=1",
                                 "Set-Cookie: SVPNCOOKIE=fixture; path=/; secure\r\n")
                elif path == "/remote/fortisslvpn_xml":
                    self.respond(conn, b'<?xml version="1.0"?><sslvpn-tunnel ver="2">'
                                       b"</sslvpn-tunnel>")
                elif path == "/remote/sslvpn-tunnel":
                    self.tunnel_requests += 1
                    self.tunnel(conn)
                    return
                else:
                    self.respond(conn)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def closed_by_client(self, conn, timeout):
        conn.settimeout(timeout)
        try:
            return conn.recv(1) == b""
        except (OSError, ssl.SSLError):
            return True

    def tunnel(self, conn):
        count = 0
        for frame in self.frames:
            size = len(frame)
            conn.sendall(bytes([(size + 6) >> 8, (size + 6) & 0xff, 0x50, 0x50,
                                size >> 8, size & 0xff]) + frame)
            if count < len(self.expected) and frame.hex() == self.expected[count]:
                count += 1
                deadline = time.monotonic() + HOLD
                while len(delivered(self.directory)) < count:
                    if time.monotonic() > deadline:
                        self.notes.append("frame %d never reached the pty" % count)
                        break
                    time.sleep(0.02)
            else:
                # A frame the client must refuse. Keep the connection open for a
                # while: a client that wrongly forwards it has time to write it
                # to the pty, where the case then sees it. A client that refuses
                # it stops by itself; the exit status is checked by the case.
                self.closed_by_client(conn, REFUSED_HOLD)
                return
        # Everything delivered: close, so the client ends the attempt.
        time.sleep(0.2)


def run_client(binary, as_root, directory, port, pin, scope, extra=()):
    argv = list(as_root) + [binary, "localhost:%d" % port, "-c", os.devnull,
                            "-u", "tester", "--password", "fixture-password",
                            "--trusted-cert", pin, "--no-routes", "--no-dns"]
    if scope:
        argv += ["--fortinet-local-cidr", scope]
    argv += list(extra)
    env = {"HOME": directory, "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "VPNT_FAKE_PPPD_DIR": directory}
    with open(os.path.join(directory, "client.log"), "wb") as log:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, env=env,
                                 start_new_session=True)
        try:
            return child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            # Only the group this fixture started, led by the PID it launched.
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            return None


def client_log(directory):
    try:
        with open(os.path.join(directory, "client.log"), errors="replace") as log:
            return log.read()
    except FileNotFoundError:
        return ""


def main():
    if sys.argv[1:] == ["--print-fake-pppd"]:
        sys.stdout.write(fake_pppd())
        return 0
    if len(sys.argv) < 7:
        print(__doc__, file=sys.stderr)
        return 2
    binary, work, cert, key, pin, scope = sys.argv[1:7]
    as_root = sys.argv[7:]
    failures = 0

    def verdict(ok, label, detail=""):
        nonlocal failures
        failures += 0 if ok else 1
        print("%s %s%s" % ("PASS" if ok else "FAIL", label,
                           ": " + detail if detail else ""))

    def start(name, frames, expected):
        directory = os.path.join(work, name)
        os.makedirs(directory)
        gateway = Gateway(cert, key, directory, frames, [f.hex() for f in expected])
        gateway.start()
        return directory, gateway

    for number, (label, frames, expected, denied) in enumerate(CASES, 1):
        directory, gateway = start("case%d" % number, frames, expected)
        code = run_client(binary, as_root, directory, gateway.port, pin, scope)
        gateway.stop()
        got = delivered(directory)
        want = [f.hex() for f in expected]
        log = client_log(directory)
        rejected = "IPCP rejected by the Fortinet local IPv4 policy" in log
        problems = []
        if code is None:
            problems.append("client timed out")
        if got != want:
            problems.append("pppd read %s, expected %s" % (got, want))
        if denied and (code != DENIED_EXIT or not rejected):
            problems.append("exit=%s rejected_logged=%s, expected exit %d and the log line"
                            % (code, rejected, DENIED_EXIT))
        if not denied and (code == DENIED_EXIT or rejected):
            problems.append("the attempt was denied (exit=%s)" % code)
        problems += gateway.notes
        verdict(not problems, label, "; ".join(problems) or
                "pppd read %d frame(s), exit %s" % (len(got), code))
        if number == 1:
            # The effective pppd argv of the attempt that went through.
            try:
                with open(os.path.join(directory, "argv"), "rb") as argv_file:
                    argv = argv_file.read().split(b"\0")[:-1]
            except FileNotFoundError:
                argv = []
            options = [a.decode("latin-1") for a in argv]
            for option in REQUIRED_ARGV:
                verdict(option in options, "pppd argv carries %s" % option,
                        "argv=%s" % options)
            verdict("nodetach" in options and "noipdefault" in options,
                    "pppd argv keeps the fixed Fortinet options", "argv=%s" % options)

    # No scope: the client must refuse before it starts pppd.
    directory, gateway = start("noscope", [LCP_A], [LCP_A])
    code = run_client(binary, as_root, directory, gateway.port, pin, "")
    gateway.stop()
    started = os.path.exists(os.path.join(directory, "argv"))
    verdict(code not in (None, 0) and not started and not delivered(directory),
            "no approved scope: pppd is never started",
            "exit=%s pppd_started=%s frames=%s" % (code, started, delivered(directory)))

    print("failures=%d" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
