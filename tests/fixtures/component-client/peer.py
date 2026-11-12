import json
import os
from pathlib import Path
import socket
import sys
import time

root, version, case = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
stream = socket.socket(fileno=0)
stream.settimeout(4)
assert stream.family == socket.AF_UNIX and stream.type == socket.SOCK_STREAM
assert stream.getsockname() == '' and stream.getpeername() == ''
assert os.getcwd() == '/' and 'VPNT_TEST_UNTRUSTED' not in os.environ
assert os.environ['VPNT_AUTH_LOCALE'] == 'pt-BR'
assert os.environ['VPNT_AUTH_UNTIL_NS'].isdecimal()
assert os.environ['SUDO_ASKPASS'] == '/Library/PrivilegedHelperTools/dev.vpnt.askpass'
(root / 'started').write_text('yes')
def send(value):
    stream.sendall(json.dumps(value).encode() + b'\n')
ready = {'type': 'ready', 'format': 1, 'version': version}
if case == 'format': ready['format'] = 99
if case == 'version': ready['version'] = '0.0.0'
send(ready)
request = b''
while True:
    chunk = stream.recv(1024)
    if not chunk: break
    request += chunk
if case in ('format', 'version'):
    assert request == b''
    stream.close()
    sys.exit(0)
assert json.loads(request) == {'id': 'remove-1'} and request.endswith(b'\n')
(root / 'request').write_bytes(request)
reply = {'type': 'removed', 'id': 'remove-1', 'component_present': True}
if case == 'id': reply['id'] = 'other-request'
if case == 'unknown': reply['uid'] = 0
if case == 'oversized': stream.sendall(json.dumps(reply).encode() + b' ' * 4096 + b'\n')
else: send(reply)
if case == 'extra': send(reply)
stream.shutdown(socket.SHUT_WR)
stream.close()
(root / 'receipt').write_text('yes')
if case == 'held':
    deadline = time.monotonic() + 5
    while not (root / 'release').exists() and time.monotonic() < deadline: time.sleep(0.005)
    assert (root / 'release').exists()
(root / 'finished').write_text('yes')
sys.exit(1 if case == 'exit' else 0)
