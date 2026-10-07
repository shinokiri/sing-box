"""Create a disposable, pinned sing dependency with shared-storage support.

The release build never runs this script. No module-cache files are modified.
"""
import json
import shutil
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[2]
version = 'v0.9.7-0.20260929150544-6f21f2425a95'
module = 'github.com/sagernet/sing'
info = json.loads(subprocess.check_output(
    ['go', 'mod', 'download', '-json', module + '@' + version], text=True))
target = root / '.study-deps' / 'sing'
if target.exists():
    raise SystemExit('Refusing to overwrite an existing study dependency')
shutil.copytree(info['Dir'], target)
for path in target.rglob('*'):
    if path.is_file():
        path.chmod(0o644)
buffer = target / 'common/buf/buffer.go'
source = buffer.read_text()
old = '\tmanaged  bool\n'
assert source.count(old) == 1
source = source.replace(old, old + '\tshared *sharedBufferStorage\n')
old = '\tcommon.Must(Put(b.data))\n\t*b = Buffer{}\n'
assert source.count(old) == 1
source = source.replace(old, '''\tif b.shared != nil {
        storage := b.shared
        *b = Buffer{}
        if storage.refs.Add(-1) == 0 {
            studySharedBytes.Add(-int64(cap(storage.data)))
            studySharedBlocks.Add(-1)
            if storage.pooled { common.Must(Put(storage.data)) }
        }
        return
    }
''' + old)
buffer.write_text(source)
for name in ('shared_buffer.go', 'shared_buffer_test.go'):
    shutil.copyfile(Path(__file__).with_name(name), target / 'common/buf' / name)
subprocess.run(['gofmt', '-w', str(target / 'common/buf')], check=True)
subprocess.run(['go', '-C', str(root / 'third_party/sing-snell'), 'mod', 'edit',
                '-replace=' + module + '=' + str(target)], check=True)
print('Shared-storage study dependency:', version)
