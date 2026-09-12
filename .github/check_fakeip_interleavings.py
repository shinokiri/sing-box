"""Test the current FakeIP implementation with temporary scheduling hooks."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("CacheFile changed; update the interleaving hooks: " + old)
    return source.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--race", action="store_true")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--run", default="^TestFakeIPInterleaving")
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    repo = Path(__file__).resolve().parent.parent
    package = repo / "experimental/cachefile"
    source = (package / "cache.go").read_text()
    source = replace_once(source, "type CacheFile struct {", """type CacheFile struct {
    testBeforeBatch func()
    testBeforeView func()
    testAfterView func()""")
    source = replace_once(source, "return db.View(fn)", """if c.testBeforeView != nil {
        c.testBeforeView()
    }
    err = db.View(fn)
    if c.testAfterView != nil {
        c.testAfterView()
    }
    return err""")
    source = replace_once(source, "err = db.Batch(fn)", """if c.testBeforeBatch != nil {
        c.testBeforeBatch()
    }
    err = db.Batch(fn)""")
    # Do not replace fakeip.go: every run exercises the current checkout.
    # The after-view hook runs after the read transaction has closed.
    with tempfile.TemporaryDirectory(prefix="fakeip-interleavings-") as directory:
        temporary = Path(directory)
        instrumented = temporary / "cache.go"
        instrumented.write_text(source)
        overlay = temporary / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {
            str(package / "cache.go"): str(instrumented),
            str(package / "fakeip_interleavings_test.go"):
                str(package / "testdata/reset_interleavings_test.go"),
        }}, indent=2) + "\n")
        command = ["go", "test", "-overlay", str(overlay),
                   "-count=" + str(args.count), "-timeout=120s", "-v",
                   "./experimental/cachefile", "-run", args.run]
        if args.race:
            command.insert(2, "-race")
        return subprocess.run(command, cwd=repo).returncode


if __name__ == "__main__":
    raise SystemExit(main())
