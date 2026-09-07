"""Check the signed APK, then collect it with matching source metadata."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from zipfile import ZipFile

client = Path("clients/android")
apks = list((client / "app/build/outputs/apk/other/release").glob("*.apk"))
if len(apks) != 1:
    raise SystemExit(f"Expected one ARM64 APK, found {apks}")
apk = apks[0]
with ZipFile(apk) as archive:
    entries = archive.namelist()
    abis = {
        name.split("/")[1]
        for name in entries
        if name.startswith("lib/") and name.endswith(".so")
    }
    if abis != {"arm64-v8a"} or "lib/arm64-v8a/libbox.so" not in entries:
        raise SystemExit(f"Unexpected APK native libraries: {sorted(abis)}")

sdk = Path(os.environ.get("ANDROID_HOME") or os.environ["ANDROID_SDK_ROOT"])
build_tools = max(
    (path for path in (sdk / "build-tools").iterdir() if all(part.isdigit() for part in path.name.split("."))),
    key=lambda path: tuple(map(int, path.name.split("."))),
)
subprocess.run([str(build_tools / "apksigner"), "verify", "--verbose", str(apk)], check=True)

props = dict(line.split("=", 1) for line in (client / "version.properties").read_text().splitlines() if "=" in line)
# Read the packaged values too: metadata must describe the APK, not merely
# the inputs to Gradle.
badging = subprocess.check_output([str(build_tools / "aapt"), "dump", "badging", str(apk)], text=True)
for field, value in (("versionCode", props["VERSION_CODE"]), ("versionName", props["VERSION_NAME"])):
    if f"{field}='{value}'" not in badging.splitlines()[0]:
        raise SystemExit(f"APK {field} does not match version.properties")
if "sdkVersion:'24'" not in badging.splitlines():
    raise SystemExit("Expected the modern API 24 APK")

metadata = {
    "version_code": int(props["VERSION_CODE"]),
    "version_name": props["VERSION_NAME"],
    "core_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "android_client_commit": subprocess.check_output(["git", "-C", str(client), "rev-parse", "HEAD"], text=True).strip(),
}
destination = Path("dist/android")
destination.mkdir(parents=True, exist_ok=True)
shutil.copy2(apk, destination / apk.name)
(destination / "SFA-version-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
print(f"Verified {apk.name}: API 24, arm64-v8a, versionCode {metadata['version_code']}")
