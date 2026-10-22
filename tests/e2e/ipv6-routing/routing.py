"""Container-local routing setup and observable dataplane assertions."""
import asyncio
import json
from pathlib import Path
import signal
import subprocess
import sys
import time

from http3_client import fetch

PUBLIC = 'fd71:7::10'
WARP = 'fd71:8::10'
CLIENT = 'fd71:9::20'


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def interface(address):
    for link in json.loads(run('ip', '-j', '-6', 'addr')):
        if any(a['local'] == address for a in link['addr_info']):
            return link['ifname']
    raise RuntimeError(f'no interface for {address}')


def ip(*args):
    return run('ip', '-6', *args)


def setup(role):
    suffix = '20' if role == 'client' else '10'
    public = interface(f'fd71:7::{suffix}')
    warp = interface(f'fd71:8::{suffix}')
    if role == 'client':
        ip('addr', 'add', CLIENT + '/128', 'dev', 'lo', 'nodad')
        ip('route', 'replace', PUBLIC + '/128', 'dev', public, 'src', CLIENT)
        return
    ip('route', 'replace', 'default', 'via', 'fd71:7::20', 'dev', public)
    ip('route', 'add', 'table', '51820', 'default', 'via', 'fd71:8::20',
       'dev', warp, 'onlink', 'src', WARP)
    ip('rule', 'add', 'pref', '100', 'from', PUBLIC + '/128', 'lookup', 'main')
    ip('rule', 'add', 'pref', '200', 'lookup', 'main', 'suppress_prefixlength', '0')
    ip('rule', 'add', 'pref', '300', 'lookup', '51820')
    for context, expected_dev, expected_src in [
        ([], warp, WARP),
        (['from', PUBLIC], public, None),
        (['from', PUBLIC, 'oif', public], public, None),
    ]:
        route = json.loads(ip('-j', 'route', 'get', CLIENT, *context, 'mark', '0'))[0]
        print(f'route get {CLIENT} {context} mark 0: {route}', flush=True)
        assert route['dev'] == expected_dev, route
        if expected_src:
            assert route['prefsrc'] == expected_src, route


def wait_for(predicate, description):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise RuntimeError(f'timed out waiting for {description}')


def observe():
    captures = []
    backend = None
    try:
        for name, device in [('public', interface(PUBLIC)), ('warp', interface(WARP)), ('backend', 'lo')]:
            log = open(f'/tmp/{name}.capture.log', 'w')
            process = subprocess.Popen(
                ['tcpdump', '-Z', 'root', '--immediate-mode', '-i', device, '-nn', '-U', '-s', '0', '-w', f'/tmp/{name}.pcap',
                 'ip6 and udp'], stdout=log, stderr=log)
            log.close()
            captures.append(process)
            wait_for(lambda: 'listening on' in Path(f'/tmp/{name}.capture.log').read_text(), name + ' capture')
        with open('/tmp/backend.log', 'w') as log:
            backend = subprocess.Popen(
                [sys.executable, '-u', '/app/http3_backend.py', '--host', '::1', '--port', '8443',
                 '--name', 'ipv6', '--hostname', 'ipv6.flightdeck.test'], stdout=log, stderr=log)
        wait_for(lambda: ':8443 ' in run('ss', '-H', '-6', '-lun') and
                 ':443 ' in run('ss', '-H', '-6', '-lun'), 'UDP listeners')
        Path('/tmp/ready').touch()
        wait_for(lambda: Path('/tmp/done').exists(), 'client completion')
    finally:
        for process in captures:
            process.send_signal(signal.SIGINT)
        for process in captures:
            process.wait(timeout=5)
        if backend:
            backend.terminate()
            backend.wait(timeout=5)
    Path('/tmp/finished').touch()


def packets(name, expression):
    return run('tcpdump', '-Z', 'root', '-nn', '-r', f'/tmp/{name}.pcap', expression).splitlines()


def check():
    replies = f'ip6 and udp src port 443 and dst host {CLIENT}'
    counts = {
        'public ingress': len(packets('public', f'ip6 and src host {CLIENT} and dst host {PUBLIC} and udp dst port 443')),
        'backend requests': len(packets('backend', 'ip6 and udp dst port 8443')),
        'backend replies': len(packets('backend', 'ip6 and udp src port 8443')),
        'public replies': len(packets('public', replies)),
        'wrong public source': len(packets('public', replies + f' and not src host {PUBLIC}')),
        'WARP replies': len(packets('warp', replies)),
    }
    print(json.dumps(counts, indent=2), flush=True)
    for name in ('public ingress', 'backend requests', 'backend replies', 'public replies'):
        assert counts[name] > 0, f'missing {name}'
    assert counts['wrong public source'] == 0, 'incorrect IPv6 reply source'
    assert counts['WARP replies'] == 0, 'asymmetric WARP egress'
    for name in ('public', 'warp', 'backend'):
        assert '0 packets dropped by kernel' in Path(f'/tmp/{name}.capture.log').read_text().splitlines(), name


def diagnostics():
    for args in [('addr',), ('rule',), ('route', 'show', 'table', 'all')]:
        print(ip(*args), flush=True)
    for path in Path('/tmp').glob('*.log'):
        print(f'{path}:\n{path.read_text()}', flush=True)
    for name in ('public', 'warp', 'backend'):
        if Path(f'/tmp/{name}.pcap').exists():
            print(f'{name}:\n' + '\n'.join(packets(name, 'ip6 and udp')), flush=True)


async def client():
    async with asyncio.timeout(10):
        await fetch(PUBLIC, 443, 'ipv6.flightdeck.test', 'hello from ipv6\n', 'v1')


if __name__ == '__main__':
    action = sys.argv[1]
    if action.startswith('setup-'):
        setup(action.removeprefix('setup-'))
    elif action == 'client':
        asyncio.run(client())
    else:
        {'observe': observe, 'check': check, 'diagnostics': diagnostics}[action]()
