"""Check the signed APK, then collect it with matching source metadata."""

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile


def inspect_elf(data):
    """Read load alignment, Android's ABI note and RELR from an ARM64 ELF."""
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Expected a little-endian ARM64 ELF")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", data, 54)
    alignments = []
    android_api = None
    relr = False
    for index in range(phnum):
        kind, _, offset, address, _, size, _, alignment = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phsize)
        if kind == 1:  # PT_LOAD: both ELF alignment and file/virtual offsets matter.
            if alignment < 16384 or (address - offset) % 16384:
                raise ValueError("Native library is not 16 KB aligned")
            alignments.append(alignment)
        elif kind == 2:  # PT_DYNAMIC; accept standard and Android RELR tags.
            for cursor in range(offset, offset + size, 16):
                tag, value = struct.unpack_from("<qQ", data, cursor)
                if tag == 0:
                    break
                if tag in (36, 0x6FFFE000) and value:
                    relr = True
        elif kind == 4:  # PT_NOTE: NT_VERSION named Android records native API.
            cursor = offset
            while cursor + 12 <= offset + size:
                name_size, desc_size, note_type = struct.unpack_from("<III", data, cursor)
                cursor += 12
                name = data[cursor:cursor + name_size].rstrip(b"\0")
                cursor += (name_size + 3) & ~3
                if name == b"Android" and note_type == 1:
                    android_api = struct.unpack_from("<I", data, cursor)[0]
                cursor += (desc_size + 3) & ~3
    if not alignments:
        raise ValueError("Native library has no load segments")
    return {"android_api": android_api, "page_alignment": min(alignments), "relr": relr}


def verify_native_libraries(archive):
    libraries = [entry for entry in archive.infolist() if entry.filename.startswith("lib/") and entry.filename.endswith(".so")]
    abis = {entry.filename.split("/")[1] for entry in libraries}
    box_name = "lib/arm64-v8a/libbox.so"
    if abis != {"arm64-v8a"} or box_name not in {entry.filename for entry in libraries}:
        raise ValueError(f"Unexpected APK native libraries: {sorted(abis)}")
    reports = {}
    for entry in libraries:
        if entry.compress_type != ZIP_STORED:
            raise ValueError(f"Native library must load directly from APK: {entry.filename}")
        report = inspect_elf(archive.read(entry))
        if report["android_api"] is not None and report["android_api"] > 36:
            raise ValueError(f"Native dependency requires newer than Android 16: {entry.filename}")
        reports[entry.filename] = report
    box = reports[box_name]
    if box["android_api"] != 35 or not box["relr"]:
        raise ValueError(f"Expected libbox built with native API 35 and RELR: {box}")
    return reports


def main():
    client = Path("clients/android")
    apks = list((client / "app/build/outputs/apk/other/release").glob("*.apk"))
    if len(apks) != 1:
        raise ValueError(f"Expected one ARM64 APK, found {apks}")
    apk = apks[0]
    with ZipFile(apk) as archive:
        native_libraries = verify_native_libraries(archive)

    sdk = Path(os.environ.get("ANDROID_HOME") or os.environ["ANDROID_SDK_ROOT"])
    build_tools = max(
        (path for path in (sdk / "build-tools").iterdir() if all(part.isdigit() for part in path.name.split("."))),
        key=lambda path: tuple(map(int, path.name.split("."))),
    )
    subprocess.run([str(build_tools / "apksigner"), "verify", "--verbose", str(apk)], check=True)
    subprocess.run([str(build_tools / "zipalign"), "-c", "-P", "16", "4", str(apk)], check=True)

    props = dict(line.split("=", 1) for line in (client / "version.properties").read_text().splitlines() if "=" in line)
    # Read the packaged values too: metadata must describe the APK, not merely
    # the inputs to Gradle.
    badging = subprocess.check_output([str(build_tools / "aapt"), "dump", "badging", str(apk)], text=True)
    for field, value in (("versionCode", props["VERSION_CODE"]), ("versionName", props["VERSION_NAME"])):
        if f"{field}='{value}'" not in badging.splitlines()[0]:
            raise ValueError(f"APK {field} does not match version.properties")
    if "sdkVersion:'36'" not in badging.splitlines():
        raise ValueError("Expected the Android 16 (API 36) APK")
    manifest = subprocess.check_output([str(build_tools / "aapt"), "dump", "xmltree", str(apk), "AndroidManifest.xml"], text=True)
    if not re.search(r"android:extractNativeLibs\([^)]*\)=\(type 0x12\)0x0\b", manifest):
        raise ValueError("APK must disable native library extraction")

    metadata = {
        "version_code": int(props["VERSION_CODE"]),
        "version_name": props["VERSION_NAME"],
        "core_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "android_client_commit": subprocess.check_output(["git", "-C", str(client), "rev-parse", "HEAD"], text=True).strip(),
        "min_sdk": 36,
        "native_libraries": native_libraries,
    }
    metadata.update(json.loads(Path("release/udpflow.json").read_text()))
    metadata["android_patch_sha256"] = hashlib.sha256(Path(".github/android-udpflow.patch").read_bytes()).hexdigest()
    destination = Path("dist/android")
    destination.mkdir(parents=True, exist_ok=True)
    apk_name = f"SFA-{props['VERSION_NAME']}-arm64-v8a.apk"
    shutil.copy2(apk, destination / apk_name)
    (destination / "SFA-version-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (destination / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in sorted(destination.iterdir()) if path.name != "SHA256SUMS"
    ))
    print(f"Verified {apk.name}: API 36, arm64-v8a, versionCode {metadata['version_code']}, uncompressed 16 KB libraries, libbox RELR")
    print(json.dumps(native_libraries, indent=2))


if __name__ == "__main__":
    main()
