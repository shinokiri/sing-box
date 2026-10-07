"""Generate the unchanged installed reader for same-binary A/B benchmarks."""
from pathlib import Path
import subprocess

BASE = 'c99d7779c639ab42e694f484a100e3188e8736ef'
path = 'third_party/sing-snell/snellv6/shaped.go'
source = subprocess.check_output(['git', 'show', BASE + ':' + path], text=True)
reader = source[source.index('type shapedReader struct {'):]
reader = reader.replace('shapedReader', 'baselineShapedReader').replace('newShapedReader', 'newBaselineShapedReader')
imports = '''// Generated baseline from installed release c99d7779; study only.
package snellv6

import (
    "crypto/cipher"
    "encoding/binary"
    "io"
    snell "github.com/sagernet/sing-snell"
    "github.com/sagernet/sing/common/buf"
    E "github.com/sagernet/sing/common/exceptions"
)

'''
Path('third_party/sing-snell/snellv6/readpath_baseline_test.go').write_text(imports + reader)
