#!/usr/bin/env python3
"""Isolated veth/netns return-path test. Not production firewall configuration."""
import os
import subprocess
import sys
import time

binary = sys.argv[1]

def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=10)

def must(*args):
    result = run(*args)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stderr}')

def backend():
    return subprocess.Popen(['ip', 'netns', 'exec', 'qsr-be', 'python3', '-u', '-c', '''
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('10.201.0.2',18443)); s.settimeout(6)
packet,peer=s.recvfrom(4096)
print(f'{peer[0]}:{peer[1]} {packet.decode()}',flush=True)
s.sendto(b'reply',peer)
'''], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def client():
    return subprocess.Popen(['ip', 'netns', 'exec', 'qsr-cl', 'python3', '-u', '-c', '''
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('10.202.0.2',41000)); s.settimeout(3)
try:
 d,a=s.recvfrom(4096);print(d.decode()+' '+str(a[1]),flush=True)
except socket.timeout:print('timeout',flush=True)
'''], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

try:
    # Creating named namespaces needs mount permissions; skip explicitly if unsupported.
    must('ip','netns','add','qsr-be')
    must('ip','netns','add','qsr-cl')
    must('ip','link','add','qsr-rbe','type','veth','peer','name','qsr-be0')
    must('ip','link','set','qsr-be0','netns','qsr-be')
    must('ip','link','add','qsr-rcl','type','veth','peer','name','qsr-cl0')
    must('ip','link','set','qsr-cl0','netns','qsr-cl')
    must('ip','addr','add','10.201.0.1/24','dev','qsr-rbe')
    must('ip','addr','add','10.202.0.1/24','dev','qsr-rcl')
    must('ip','link','set','qsr-rbe','up')
    must('ip','link','set','qsr-rcl','up')
    for ns, interface, address, gateway in [('qsr-be','qsr-be0','10.201.0.2/24','10.201.0.1'),('qsr-cl','qsr-cl0','10.202.0.2/24','10.202.0.1')]:
        must('ip','-n',ns,'link','set','lo','up')
        must('ip','-n',ns,'addr','add',address,'dev',interface)
        must('ip','-n',ns,'link','set',interface,'up')
        must('ip','-n',ns,'route','add','default','via',gateway)
    must('ip','rule','add','pref','100','fwmark','0x100','lookup','100')
    must('ip','route','add','local','0.0.0.0/0','dev','lo','table','100')
    must('nft','add','table','inet','qsr_test')
    must('nft','add','chain','inet','qsr_test','prerouting','{ type filter hook prerouting priority mangle; policy accept; }')
except Exception as exc:
    print('SKIP: isolated network setup unavailable:',exc, file=sys.stderr)
    for ns in ('qsr-be','qsr-cl'):
        run('ip','netns','del',ns)
    sys.exit(77)

try:
    rule = ['nft','add','rule','inet','qsr_test','prerouting','iifname','qsr-rbe','ip','saddr','10.201.0.2','udp','sport','18443','socket','transparent','1','meta','mark','set','0x100']
    must(*rule)
    for positive in (True, False):
        if not positive:
            must('nft','flush','chain','inet','qsr_test','prerouting')
        b = backend()
        c = client()
        time.sleep(.25)
        result = run(binary,'--transparent-e2e-positive' if positive else '--transparent-e2e-negative')
        bout,berr = b.communicate(timeout=8)
        cout,cerr = c.communicate(timeout=8)
        if result.returncode or '10.202.0.2:41000 request' not in bout:
            raise AssertionError(f'backend IP/port or flow failed: {result.stderr} {bout} {berr}')
        if positive and 'reply 18444' not in cout:
            raise AssertionError(f'client missed routed reply: {cout} {cerr}')
        if not positive and cout.strip() != 'timeout':
            raise AssertionError(f'unmarked negative probe unexpectedly got a response: {cout}')
        print('PASS: transparent', 'return delivery and real client tuple' if positive else 'no-mark fail-closed probe')
finally:
    run('nft','delete','table','inet','qsr_test')
    for ns in ('qsr-be','qsr-cl'):
        run('ip','netns','del',ns)
    for interface in ('qsr-rbe','qsr-rcl'):
        run('ip','link','del',interface)
