#!/usr/bin/env python3
"""Transparent-mode return paths in throwaway network namespaces.

run.sh starts this inside `unshare -rn`, so the current namespace plays the
router host and nothing here touches the real host network. The backend and
client namespaces are held by child processes and entered by PID; unlike
`ip netns`, that needs no /run or /sys mounts, so it also works in containers.

Each case installs one return-path recipe exactly as README.md documents it,
then checks the tuple the backend saw and where the client's reply came from.
"""
import os
import shutil
import subprocess
import sys
import time

if os.environ.get('QSR_TRANSPARENT_NETNS') != '1':
    sys.exit('run tests/e2e/transparent/run.sh instead: this script rewrites routing in the current network namespace')

binary = sys.argv[1]

BACKEND = '''
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, port))
s.settimeout(6)
print('ready', flush=True)
packet, peer = s.recvfrom(4096)
print(peer[0], peer[1], packet.decode(), flush=True)
s.sendto(b'reply', peer)
'''

# Prints the first packet and its source, or nothing on timeout.
CLIENT = '''
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, port))
s.settimeout(4)
print('ready', flush=True)
try:
    packet, peer = s.recvfrom(4096)
    print(peer[0], peer[1], packet.decode(), flush=True)
except socket.timeout:
    pass
'''


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=10)


def must(*args):
    result = run(*args)
    if result.returncode:
        raise RuntimeError(f'{" ".join(args)}: {result.stderr.strip()}')


def namespace():
    holder = subprocess.Popen(['unshare', '-n', 'sleep', '600'])
    own = os.readlink('/proc/self/ns/net')
    for _ in range(200):
        if os.readlink(f'/proc/{holder.pid}/ns/net') != own:
            return holder
        time.sleep(0.01)
    holder.kill()
    raise RuntimeError('network namespace holder did not start')


def inside(holder, *args):
    return ('nsenter', '-t', str(holder.pid), '-n', *args) if holder else args


def spawn(holder, code, host, port):
    process = subprocess.Popen(list(inside(holder, 'python3', '-u', '-c', code, host, str(port))),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if process.stdout.readline() != 'ready\n':
        process.kill()
        raise AssertionError(f'{host}:{port} did not start: {process.communicate()[1]}')
    return process


holders = []
try:
    backend_ns = namespace()
    holders.append(backend_ns)
    client_ns = namespace()
    holders.append(client_ns)
    for holder, router_if, peer_if, v4, v6 in ((backend_ns, 'qsr-rbe', 'be0', '10.201.0', 'fd01:'),
                                               (client_ns, 'qsr-rcl', 'cl0', '10.202.0', 'fd02:')):
        must('ip', 'link', 'add', 'name', router_if, 'type', 'veth', 'peer', 'name', peer_if)
        must('ip', 'link', 'set', peer_if, 'netns', str(holder.pid))
        must('ip', 'addr', 'add', f'{v4}.1/24', 'dev', router_if)
        must('ip', '-6', 'addr', 'add', f'{v6}:1/64', 'dev', router_if, 'nodad')
        must('ip', 'link', 'set', router_if, 'up')
        must(*inside(holder, 'ip', 'link', 'set', 'lo', 'up'))
        must(*inside(holder, 'ip', 'addr', 'add', f'{v4}.2/24', 'dev', peer_if))
        must(*inside(holder, 'ip', '-6', 'addr', 'add', f'{v6}:2/64', 'dev', peer_if, 'nodad'))
        must(*inside(holder, 'ip', 'link', 'set', peer_if, 'up'))
        # Replies to client addresses go back through the router host, as README.md requires of remote backends.
        must(*inside(holder, 'ip', 'route', 'add', 'default', 'via', f'{v4}.1'))
        must(*inside(holder, 'ip', '-6', 'route', 'add', 'default', 'via', f'{v6}:1'))
    must('ip', '-4', 'route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '100')
    must('ip', '-6', 'route', 'add', 'local', '::/0', 'dev', 'lo', 'table', '100')
    # Link-local addresses still run duplicate address detection after link-up,
    # and IPv6 neighbour discovery does not answer until they are usable.
    for _ in range(100):
        if all(not run(*inside(holder, 'ip', '-6', 'addr', 'show', 'tentative')).stdout.strip()
               for holder in (None, backend_ns, client_ns)):
            break
        time.sleep(0.1)
    else:
        raise RuntimeError('IPv6 addresses stayed tentative')
except (OSError, RuntimeError) as exc:
    print('SKIP: isolated network setup unavailable:', exc, file=sys.stderr)
    for holder in holders:
        holder.kill()
    sys.exit(77)

v4 = {'client': ('10.202.0.2', 41000), 'listener': ('10.202.0.1', 18444), 'backend': ('10.201.0.2', 18443)}
v6 = {'client': ('fd02::2', 41000), 'listener': ('fd02::1', 18444), 'backend': ('fd01::2', 18443)}
same_host = {**v4, 'backend': ('127.0.0.1', 18443)}


def source_rule(family, backend):
    return ([('ip', family, 'rule', 'add', 'pref', '90', 'from', backend, 'ipproto', 'udp', 'sport', '18443',
              'lookup', '100')],
            [('ip', family, 'rule', 'del', 'pref', '90')])


nft_socket_match = (
    [('nft', 'add', 'table', 'inet', 'qsr'),
     ('nft', 'add', 'chain', 'inet', 'qsr', 'prerouting', '{ type filter hook prerouting priority mangle; }'),
     ('nft', 'add', 'rule', 'inet', 'qsr', 'prerouting', 'ip', 'saddr', '10.201.0.2', 'udp', 'sport', '18443',
      'socket', 'transparent', '1', 'meta', 'mark', 'set', '0x100'),
     ('ip', '-4', 'rule', 'add', 'pref', '90', 'fwmark', '0x100', 'lookup', '100')],
    [('nft', 'delete', 'table', 'inet', 'qsr'), ('ip', '-4', 'rule', 'del', 'pref', '90')])

no_return_path = ([], [])

# name, addresses, backend namespace (None: router host), (setup, cleanup), reply expected
cases = [
    ('IPv4 backend, source rule', v4, backend_ns, source_rule('-4', '10.201.0.2'), True),
    ('IPv6 backend, source rule', v6, backend_ns, source_rule('-6', 'fd01::2'), True),
    ('same-host 127.0.0.1 backend, source rule', same_host, None, source_rule('-4', '127.0.0.1'), True),
    ('IPv4 backend, nft socket match', v4, backend_ns, nft_socket_match, True),
    ('IPv4 backend, no return path', v4, backend_ns, no_return_path, False),
    ('IPv6 backend, no return path', v6, backend_ns, no_return_path, False),
    ('same-host 127.0.0.1 backend, no return path', same_host, None, no_return_path, False),
]

skipped = []
try:
    for name, addresses, backend_holder, (setup, cleanup), expect_reply in cases:
        try:
            for args in setup:
                must(*args)
        except (OSError, RuntimeError) as exc:
            for args in cleanup:
                if shutil.which(args[0]):
                    run(*args)
            if setup[0][0] != 'nft':
                raise
            # The nft `socket` expression needs the nft_socket module, which a user namespace cannot load.
            skipped.append(name)
            print(f'SKIP: transparent {name}: {exc}', file=sys.stderr)
            continue
        try:
            backend = spawn(backend_holder, BACKEND, *addresses['backend'])
            client = spawn(client_ns, CLIENT, *addresses['client'])
            endpoints = [str(part) for key in ('client', 'backend', 'listener') for part in addresses[key]]
            router = run(binary, '--transparent-e2e', 'reply' if expect_reply else 'silent', *endpoints)
            backend_out, backend_err = backend.communicate(timeout=10)
            client_out, client_err = client.communicate(timeout=10)
        finally:
            for args in cleanup:
                run(*args)
        client_ip, client_port = addresses['client']
        listener_ip, listener_port = addresses['listener']
        if router.returncode:
            raise AssertionError(f'{name}: router flow failed: {router.stderr} backend: {backend_out!r} {backend_err}')
        if backend_out.strip() != f'{client_ip} {client_port} request':
            raise AssertionError(f'{name}: backend did not see the client tuple: {backend_out!r} {backend_err}')
        from_listener = f'{listener_ip} {listener_port} '
        if expect_reply and client_out.strip() != from_listener + 'reply':
            raise AssertionError(f'{name}: client missed the reply through the listener: {client_out!r} {client_err}')
        if not expect_reply and from_listener in client_out:
            raise AssertionError(f'{name}: reply reached the client without a return path: {client_out!r}')
        print(f'PASS: transparent {name}')
finally:
    for holder in holders:
        holder.kill()
if skipped:
    print(f'{len(skipped)} case(s) skipped', file=sys.stderr)
