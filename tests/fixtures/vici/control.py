"""Independent VICI peer; fictional credentials and SA metadata only."""
import copy
import select
import socket
import sys
import time

path, audit, mode = sys.argv[1:]
name = 'vpnt-502-43617365-7'
child = name + '-child'


def exact(wire, length):
    value = b''
    while len(value) < length:
        part = wire.recv(length - len(value))
        if not part:
            raise EOFError('incomplete frame')
        value += part
    return value


def decode(data):
    at = 0

    def take(length):
        nonlocal at
        value = data[at:at + length]
        assert len(value) == length
        at += length
        return value

    def blob():
        return take(int.from_bytes(take(2), 'big')).decode('ascii')

    def message(nested=False):
        result = {}
        while at < len(data):
            tag = take(1)[0]
            if tag == 2 and nested:
                return result
            key = take(take(1)[0]).decode('ascii')
            assert key not in result
            if tag == 1:
                value = message(True)
            elif tag == 3:
                value = blob()
            else:
                assert tag == 4
                value = []
                while True:
                    tag = take(1)[0]
                    if tag == 6:
                        break
                    assert tag == 5
                    value.append(blob())
            result[key] = value
        assert not nested
        return result

    return message()


def encode(message):
    result = b''
    for key, value in message.items():
        key = bytes([len(key)]) + key.encode('ascii')
        if isinstance(value, dict):
            result += b'\x01' + key + encode(value) + b'\x02'
        elif isinstance(value, list):
            result += b'\x04' + key
            for item in value:
                item = item if isinstance(item, bytes) else item.encode('ascii')
                result += b'\x05' + len(item).to_bytes(2, 'big') + item
            result += b'\x06'
        else:
            value = value if isinstance(value, bytes) else value.encode('ascii')
            result += b'\x03' + key + len(value).to_bytes(2, 'big') + value
    return result


def packet(wire):
    length = int.from_bytes(exact(wire, 4), 'big')
    assert 0 < length <= 512 * 1024
    body = exact(wire, length)
    assert body[0] in (0, 3)
    length = body[1]
    return body[0], body[2:2 + length].decode('ascii'), decode(body[2 + length:])


def send(wire, message, event=False):
    body = (b'\x07\x07list-sa' if event else b'\x01') + encode(message)
    wire.sendall(len(body).to_bytes(4, 'big') + body)


def sas():
    if mode == 'empty':
        return []
    c = {'name': child, 'uniqueid': '1', 'reqid': '16383', 'state': 'INSTALLED',
         'mode': 'TUNNEL', 'protocol': 'ESP', 'spi-in': 'abcd0102', 'spi-out': 'abcd0103',
         'local-ts': ['10.8.0.2/32'], 'remote-ts': ['10.20.0.0/24']}
    ike = {'uniqueid': '1', 'version': '2', 'state': 'ESTABLISHED', 'initiator': 'yes',
           'local-host': '192.0.2.2', 'remote-host': '198.51.100.3',
           'local-port': '45000', 'remote-port': '500',
           'initiator-spi': '0123456789abcdef', 'responder-spi': 'fedcba9876543210',
           'local-vips': ['10.8.0.2'], 'child-sas': {child + '-1': c}}
    if mode == 'ipv6':
        ike['local-vips'] = ['2001:db8:8::2']
        c['local-ts'], c['remote-ts'] = ['2001:db8:8::2/128'], ['2001:db8:20::/64']
    if mode == 'duplicate-spi':
        c2 = copy.deepcopy(c)
        c2['uniqueid'] = '2'
        ike['child-sas'][child + '-2'] = c2
    if mode == 'too-many':
        ike['child-sas'] = {}
        for number in range(1, 258):
            c2 = copy.deepcopy(c)
            c2['uniqueid'] = str(number)
            c2['spi-in'], c2['spi-out'] = f'{0xabcd0000 + number:08x}', f'{0xabce0000 + number:08x}'
            ike['child-sas'][f'{child}-{number}'] = c2
    if mode == 'rekey':
        ike['state'] = 'REKEYED'
        c['state'] = 'REKEYED'
        fresh = copy.deepcopy(ike)
        fresh['state'], fresh['uniqueid'] = 'ESTABLISHED', '2'
        c2 = copy.deepcopy(c)
        c2['state'], c2['uniqueid'] = 'INSTALLED', '2'
        c2['spi-in'], c2['spi-out'] = 'abcd0104', 'abcd0105'
        fresh['child-sas'] = {child + '-2': c2, child + '-3': {
            'name': child, 'uniqueid': '3', 'reqid': '0', 'state': 'CREATED',
            'mode': 'TUNNEL', 'local-ts': [], 'remote-ts': []}}
        return [{name: ike}, {name: fresh}]
    if mode in ('compatible-overlap', 'overlap-conflict'):
        c['state'] = 'REKEYING'
        c2 = copy.deepcopy(c)
        c2['uniqueid'], c2['state'] = '2', 'INSTALLED'
        c2['spi-in'], c2['spi-out'] = 'abcd0104', 'abcd0105'
        if mode == 'overlap-conflict':
            c2['remote-ts'] = ['10.20.0.0/25']
        ike['child-sas'] = {child + '-1': c, child + '-2': c2}
    if mode == 'inactive-only':
        ike['state'] = 'REKEYED'
        c['state'] = 'REKEYED'
    if mode == 'narrowed':
        c['remote-ts'] = ['10.20.0.0/25']
    changes = {'bad-reqid': (c, 'reqid', '42'), 'bad-spi': (c, 'spi-in', '00000000'),
               'bad-remote-ts': (c, 'remote-ts', ['10.21.0.0/24']),
               'wide-local-ts': (c, 'local-ts', ['0.0.0.0/0']),
               'bad-child-name': (c, 'name', 'foreign-child'), 'bad-state': (c, 'state', 'UNKNOWN'),
               'bad-version': (ike, 'version', '1'), 'bad-endpoint': (ike, 'remote-host', '198.51.100.4'),
               'bad-uniqueid': (ike, 'uniqueid', '01'), 'bad-mode': (c, 'mode', 'TRANSPORT'),
               'bad-protocol': (c, 'protocol', 'AH'), 'bad-vip': (ike, 'local-vips', ['0.0.0.0']),
               'bad-child-key': (ike, 'child-sas', {child + '-9': c}),
               'zero-port': (ike, 'local-port', '0'), 'bad-encap': (c, 'encap', {}),
               'wide-remote-ts': (c, 'remote-ts', ['10.20.0.0/16']),
               'mismatch-family': (c, 'remote-ts', ['2001:db8:20::/64']),
               'responder': (ike, 'initiator', 'no'), 'zero-ike-spi': (ike, 'initiator-spi', '0000000000000000'),
               'spi-width': (c, 'spi-in', 'abcdef'), 'zero-id': (ike, 'uniqueid', '0'),
               'zero-reqid': (c, 'reqid', '0')}
    if mode in changes:
        target, key, value = changes[mode]
        target[key] = value
    if mode == 'bad-vip':
        c['local-ts'] = ['0.0.0.0/32']
    if mode == 'partial-bad':
        bad = copy.deepcopy(ike)
        bad['uniqueid'] = '2'
        bad['child-sas'][child + '-1']['reqid'] = '42'
        return [{name: ike}, {name: bad}]
    if mode == 'foreign-root':
        return [{'foreign': ike}]
    if mode in ('duplicate-ike', 'duplicate-child'):
        fresh = copy.deepcopy(ike)
        fresh['uniqueid'] = '1' if mode == 'duplicate-ike' else '2'
        c2 = copy.deepcopy(c)
        c2['uniqueid'] = '2' if mode == 'duplicate-ike' else '1'
        c2['spi-in'], c2['spi-out'] = 'abcd0104', 'abcd0105'
        fresh['child-sas'] = {child + '-' + c2['uniqueid']: c2}
        return [{name: ike}, {name: fresh}]
    if mode == 'root-extra':
        return [{name: ike, 'unexpected': 'value'}]
    return [{name: ike}]


PLUGINS = [
    'kernel-libipsec', 'kernel-pfroute', 'socket-default', 'vici',
    'aes', 'des', 'sha1', 'sha2', 'hmac', 'kdf', 'random', 'nonce',
    'openssl', 'eap-identity', 'eap-mschapv2',
]


def stats():
    plugins = list(PLUGINS)
    if mode == 'stats-missing':
        return {'uptime': '1'}
    if mode == 'stats-scalar':
        return {'plugins': 'kernel-libipsec', 'uptime': '1'}
    if mode == 'stats-section':
        return {'plugins': {'kernel-libipsec': {}}, 'uptime': '1'}
    if mode == 'stats-empty':
        return {'plugins': [], 'uptime': '1'}
    if mode == 'stats-duplicate':
        plugins.append('vici')
    elif mode == 'stats-uppercase':
        plugins[0] = 'Kernel-Libipsec'
    elif mode == 'stats-underscore':
        plugins.append('bad_name')
    elif mode == 'stats-long':
        plugins.append('a' * 65)
    elif mode == 'stats-pfkey':
        plugins.append('kernel-pfkey')
    elif mode == 'stats-netlink':
        plugins.append('kernel-netlink')
    elif mode == 'stats-no-libipsec':
        plugins.remove('kernel-libipsec')
    elif mode == 'stats-no-pfroute':
        plugins.remove('kernel-pfroute')
    elif mode == 'stats-no-socket':
        plugins.remove('socket-default')
    elif mode == 'stats-no-vici':
        plugins.remove('vici')
    elif mode == 'stats-128':
        plugins = plugins + [f'x{number}' for number in range(128 - len(PLUGINS))]
    elif mode == 'stats-129':
        plugins = plugins + [f'x{number}' for number in range(129 - len(PLUGINS))]
    elif mode == 'stats-name64':
        plugins.append('n' * 64)
    elif mode == 'stats-empty-item':
        plugins.append('')
    elif mode == 'stats-invalid-utf8':
        plugins.append(b'bad\xffname')
    elif mode == 'stats-extra':
        plugins = list(reversed(plugins)) + ['pem', 'x509']
    return {'plugins': plugins, 'uptime': '1'}


server = socket.socket(socket.AF_UNIX)
server.bind(path)
server.listen(4)
print('ready', flush=True)
counts = {}
held = []
expires = time.monotonic() + 10
while time.monotonic() < expires:
    ready, _, _ = select.select([server, sys.stdin], [], [], 0.05)
    if sys.stdin in ready:
        break
    if server not in ready:
        continue
    wire, _ = server.accept()
    wire.settimeout(2)
    try:
        tag, command, request = packet(wire)
    except (EOFError, ConnectionResetError):
        wire.close()
        continue
    if tag == 3:
        assert command == 'list-sa' and request == {}
        wire.sendall(b'\0\0\0\x01\x05')
        tag, command, request = packet(wire)
    assert tag == 0
    counts[command] = counts.get(command, 0) + 1
    with open(audit, 'a', encoding='ascii') as output:
        output.write(command + '\n')
    if command == 'version':
        send(wire, {'daemon': 'foreign' if mode == 'incompatible-daemon' else 'charon', 'version': '9.0' if mode == 'incompatible' else '6.1.0'})
    elif command == 'stats':
        send(wire, stats())
    elif command == 'list-sas':
        assert request == {'ike': name}
        for item in sas():
            send(wire, item, True)
        send(wire, {'success': 'yes'} if mode == 'nonempty-completion' else {})
    else:
        if command == 'load-conn':
            assert list(request) == [name]
            assert request[name]['children'][child]['reqid'] == '16383'
        elif command == 'load-shared':
            kind = 'eap' if request['type'] == 'EAP' else 'psk'
            assert request['id'] == name + '-' + kind
            assert request['data'] == ('fictional-eap-password' if kind == 'eap' else 'fictional-gateway-key')
        elif command in ('initiate', 'terminate'):
            assert request['ike'] == name and request['loglevel'] == '-1'
            assert 0 < int(request['timeout']) <= 120000
            if command == 'initiate':
                assert request['child'] == child
        elif command == 'unload-conn':
            assert request == {'name': name}
        elif command == 'unload-shared':
            assert request['id'] in (name + '-eap', name + '-psk')
        else:
            raise RuntimeError('unknown command')
        if mode == 'hold-initiate' and command == 'initiate':
            held.append(wire)
            continue
        failed = mode == f'{command}:{counts[command]}'
        send(wire, {'success': 'no', 'errmsg': 'fictional-secret-must-not-leak'} if failed else {'success': 'yes'})
    wire.close()
