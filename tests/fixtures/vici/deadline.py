"""Independent, bounded VICI peer. FD 2 is an owned cleanup barrier, not stderr."""
import socket
import sys

wire = socket.socket(fileno=0)
control = socket.socket(fileno=2)
wire.settimeout(5)
control.settimeout(5)
mode = sys.argv[1]


def exact(length):
    value = b''
    while len(value) < length:
        chunk = wire.recv(length - len(value))
        if not chunk:
            raise RuntimeError('incomplete frame')
        value += chunk
    return value


def frame():
    length = int.from_bytes(exact(4), 'big')
    assert 0 < length <= 512 * 1024
    return exact(length)


print('ready', flush=True)
if mode == 'write':
    length = int.from_bytes(exact(4), 'big')
    assert 400_000 < length <= 512 * 1024
elif mode == 'subscription':
    assert frame() == b'\x03\x07list-sa'
else:
    assert frame() == b'\x00\x07version'
    if mode == 'fragment':
        wire.sendall(b'\x00\x00')
    elif mode == 'reply':
        wire.sendall(b'\x00\x00\x00\x01\x01')

print('waiting', flush=True)
assert control.recv(1) == b'R'
if mode == 'write':
    received = 0
    while received < length:
        chunk = wire.recv(min(65536, length - received))
        if not chunk:
            break
        received += len(chunk)
    print(f'body:{received}/{length}', flush=True)
    if received == length:
        wire.sendall(b'\x00\x00\x00\x01\x01')
