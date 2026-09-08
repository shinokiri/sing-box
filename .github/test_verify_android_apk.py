import importlib.util
import io
from pathlib import Path
import struct
import unittest
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

spec = importlib.util.spec_from_file_location("verify_android_apk", Path(__file__).with_name("verify_android_apk.py"))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def native_library(api=35, alignment=16384, load_offset=0, relr_tag=36):
    # Small ELF64 fixture with one LOAD, Android API note and dynamic table.
    data = bytearray(512)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 183)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 3)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, load_offset, 0, 0, len(data), len(data), alignment)
    struct.pack_into("<IIQQQQQQ", data, 120, 4, 4, 256, 256, 256, 24, 24, 4)
    struct.pack_into("<IIQQQQQQ", data, 176, 2, 6, 288, 288, 288, 32, 32, 8)
    data[256:280] = struct.pack("<III", 8, 4, 1) + b"Android\0" + struct.pack("<I", api)
    struct.pack_into("<qQ", data, 288, relr_tag, 0x1000)
    return data


class NativeApkTest(unittest.TestCase):
    def verify_archive(self, entries, compression=ZIP_STORED):
        stream = io.BytesIO()
        with ZipFile(stream, "w", compression=compression) as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        with ZipFile(stream) as archive:
            return verify.verify_native_libraries(archive)

    def test_reads_native_api_alignment_and_both_relr_encodings(self):
        for tag in (36, 0x6FFFE000):
            with self.subTest(tag=tag):
                self.assertEqual(verify.inspect_elf(native_library(relr_tag=tag)), {"android_api": 35, "page_alignment": 16384, "relr": True})

    def test_rejects_four_k_loads_and_misaligned_file_offsets(self):
        for data in (native_library(alignment=4096), native_library(load_offset=4096)):
            with self.assertRaisesRegex(ValueError, "16 KB aligned"):
                verify.inspect_elf(data)

    def test_new_apk_cannot_silently_package_old_libbox_or_disable_relr(self):
        for data in (native_library(api=24), native_library(relr_tag=7)):
            with self.assertRaisesRegex(ValueError, "Expected libbox built with native API 35 and RELR"):
                self.verify_archive({"lib/arm64-v8a/libbox.so": data})

    def test_checks_dependencies_as_well_as_libbox(self):
        entries = {"lib/arm64-v8a/libbox.so": native_library(), "lib/arm64-v8a/libdependency.so": native_library(api=21, relr_tag=7)}
        self.assertEqual(len(self.verify_archive(entries)), 2)
        entries["lib/arm64-v8a/libdependency.so"] = native_library(api=21, alignment=4096)
        with self.assertRaisesRegex(ValueError, "16 KB aligned"):
            self.verify_archive(entries)
        entries["lib/arm64-v8a/libdependency.so"] = native_library(api=37)
        with self.assertRaisesRegex(ValueError, "newer than Android 16"):
            self.verify_archive(entries)

    def test_compressed_libraries_cannot_pass_direct_loading_gate(self):
        with self.assertRaisesRegex(ValueError, "load directly from APK"):
            self.verify_archive({"lib/arm64-v8a/libbox.so": native_library()}, ZIP_DEFLATED)

    def test_rejects_extra_abis_missing_libbox_and_mislabeled_elf(self):
        for entries in (
            {"lib/arm64-v8a/libdependency.so": native_library()},
            {"lib/arm64-v8a/libbox.so": native_library(), "lib/x86_64/libbox.so": native_library()},
        ):
            with self.assertRaisesRegex(ValueError, "Unexpected APK native libraries"):
                self.verify_archive(entries)
        mislabeled = native_library()
        struct.pack_into("<H", mislabeled, 18, 62)
        with self.assertRaisesRegex(ValueError, "ARM64 ELF"):
            self.verify_archive({"lib/arm64-v8a/libbox.so": mislabeled})


if __name__ == "__main__":
    unittest.main()
