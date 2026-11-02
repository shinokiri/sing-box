"""Embed the BPF ELF and its identity in the one distributed native loader."""
import hashlib
from pathlib import Path
import sys

data = Path(sys.argv[1]).read_bytes()
digest = hashlib.sha256(data).digest()
with Path(sys.argv[2]).open('w') as out:
    out.write('/* Generated from synack.bpf.o; do not edit. */\n')
    for name, value in [('ctfo_object', data), ('ctfo_build', digest)]:
        out.write('static const unsigned char ' + name + '[] = {\n')
        for i in range(0, len(value), 16):
            out.write(','.join(str(b) for b in value[i:i+16]) + ',\n')
        out.write('};\n')
