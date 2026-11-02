"""Root-only, isolated TCX lifecycle and packet tests; no live interface changes.

Usage: sudo python3 lifecycle-test.py /absolute/path/to/snell-tfo-compat
Requires iproute2, libbpf.so.1, bpffs and a kernel with TCX (Linux 6.6+).
"""
import ctypes as C
import errno
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys

binary = str(Path(sys.argv[1]).resolve())
name = 'ctfo' + str(os.getpid())
assert len(name) < 16
root = Path('/sys/fs/bpf/snell-tfo-compat')
ports = [23791, 23792]
instances = [root / f'{name}-{port}' for port in ports]
assert all(not p.exists() for p in instances)
assert subprocess.run(['ip', 'link', 'show', name], capture_output=True).returncode != 0
lib = C.CDLL('libbpf.so.1', use_errno=True)
lib.bpf_obj_get.argtypes = [C.c_char_p]
lib.bpf_map_update_elem.argtypes = [C.c_int, C.c_void_p, C.c_void_p, C.c_uint64]
checks = []
created = False


def check(name, value):
    assert value, name
    checks.append(name)


def command(action, port=23791, ok=True, limit=None):
    def constrain():
        resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))
    p = subprocess.run([binary, action, '--interface=' + name, '--port=' + str(port)],
                       capture_output=True, text=True, timeout=10,
                       preexec_fn=constrain if limit else None)
    if ok:
        assert p.returncode == 0, (p.args, p.stderr, p.stdout)
    return p


def status(port=23791):
    return json.loads(command('status', port).stdout)


try:
    subprocess.run(['ip', 'link', 'add', name, 'type', 'dummy'], check=True)
    created = True
    original = json.loads(command('attach').stdout)
    check('fresh attachment is active', original['active'])
    check('repeated attachment retains every object ID', json.loads(command('attach').stdout) == original)
    check('pins outlive loader process', status() == original)
    other = json.loads(command('attach', 23792).stdout)
    check('two instances coexist on the same TCX hooks', other['active'] and status() == original)
    zero = C.c_uint32()
    fd = lib.bpf_obj_get(str(instances[0] / 'config').encode())
    assert fd >= 0
    value = C.create_string_buffer(48)
    rc = lib.bpf_map_update_elem(fd, C.byref(zero), value, 0)
    os.close(fd)
    check('ownership configuration is frozen', rc == -1 and C.get_errno() == errno.EPERM)

    p = subprocess.run(['python3', str(Path(__file__).with_name('packet-test.py')),
                        str(instances[0] / 'pending')], input=json.dumps(original['programs']),
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    packet = json.loads(p.stdout)
    counters = status()['counters']
    check('real kernel packet checks passed', packet['passed'] and packet['checks'] >= 90)
    check('adapted handshakes and rejected early data are observable',
          counters['marked_syn'] >= 6 and counters['adapted_synack'] >= 12 and counters['rejected_early_data'] >= 4)
    check('normal operation has no state or write failures', counters['state_error'] == counters['write_error'] == 0)

    unknown = instances[0] / 'unknown'
    unknown.mkdir()
    check('unknown state refuses both attachment and removal',
          command('attach', ok=False).returncode != 0 and command('detach', ok=False).returncode != 0)
    unknown.rmdir()
    check('refused operation preserves owned live hooks', status()['programs'] == original['programs'])
    (instances[0] / 'ingress').unlink()
    check('incomplete instance reports inactive', not status()['active'])
    recovered = json.loads(command('attach').stdout)
    check('incomplete owned instance recovers', recovered['active'] and recovered['programs'] != original['programs'])
    check('recovery preserves unrelated TCX instance', status(23792) == other)

    command('detach')
    command('detach')
    check('detachment is idempotent and removes all owned pins', not instances[0].exists() and not status()['active'])
    check('detachment preserves unrelated instance', status(23792) == other)

    # Restrict descriptors to exercise real load/attach/pin failures, rather
    # than replacing loader operations with successful mocks.
    failures = []
    for limit in range(8, 25):
        p = command('attach', ok=False, limit=limit)
        if p.returncode:
            failures.append({'fd_limit': limit, 'last_error': p.stderr.splitlines()[-1:]})
            check(f'failure at descriptor limit {limit} leaves no owned pins', not instances[0].exists())
        else:
            command('detach')
    check('descriptor exhaustion exercised failure cleanup', len(failures) > 0)
    check('failed creation preserves unrelated instance', status(23792) == other)

    command('attach')
    subprocess.run(['ip', 'link', 'delete', name], check=True)
    created = False
    check('device removal makes both instances inactive', not status()['active'] and not status(23792)['active'])
    command('detach'); command('detach', 23792)
    subprocess.run(['ip', 'link', 'add', name, 'type', 'dummy'], check=True)
    created = True
    recreated = json.loads(command('attach').stdout)
    check('same device name with a new ifindex is supported', recreated['active'] and recreated['ifindex'] != original['ifindex'])
    command('detach')
    result = {'passed': True, 'checks': checks, 'packet': packet, 'counters': counters, 'failure_cases': failures}
finally:
    for port, path in zip(ports, instances):
        if (path / 'unknown').exists(): (path / 'unknown').rmdir()
        command('detach', port, ok=False)
    if created:
        subprocess.run(['ip', 'link', 'delete', name], check=True)
    for port in ports:
        Path(f'/run/snell-tfo-compat/{name}-{port}.lock').unlink(missing_ok=True)
    assert all(not p.exists() for p in instances)

print(json.dumps(result))
