from common import METADATA, STAGING, OVERLAYS
import common as c
import errno
import json
import os
import subprocess
import tarfile
import time
import unittest as t

DEBUGENV = {"RUST_LOG": "TRACE", "RUST_LOG_BLOCKING": "1"}

OVERLAY1_META = OVERLAYS + "/overlay1.metadata"

INIT_DIRS = [
    STAGING,
    METADATA,
    OVERLAYS + "/overlay1",
    OVERLAYS + "/overlay2",
    OVERLAYS + "/overlay3",
    OVERLAYS + "/overlay1/dir1",
    OVERLAYS + "/overlay2/dir1",
    OVERLAYS + "/overlay3/dir1",
    OVERLAY1_META + "/rootfs/chld/file0",
    STAGING + "/dir1",
]
INIT_FILES = {
    METADATA + "/config.json": json.dumps({
        "mounts": [
            {
                "source": os.path.abspath(OVERLAYS + "/overlay1"),
                "target": os.path.abspath(STAGING),
                "fstype": "overlay"
            },
            {
                "source": os.path.abspath(OVERLAYS + "/overlay2"),
                "target": os.path.abspath(STAGING),
                "fstype": "overlay"
            },
            {
                "source": os.path.abspath(OVERLAYS + "/overlay3"),
                "target": os.path.abspath(STAGING),
                "fstype": "overlay"
            }
        ]
    }),
    OVERLAYS + "/overlay1/file0": "_",
    OVERLAYS + "/overlay1/file1": "0",
    OVERLAYS + "/overlay1/file2": "1",
    OVERLAYS + "/overlay2/file1": "2",
    OVERLAYS + "/overlay2/file2": "3",
    OVERLAYS + "/overlay2/file3": "4",
    OVERLAYS + "/overlay3/file3": "6",
    OVERLAYS + "/overlay3/file4": "7",
    STAGING + "/file1": "8",
    STAGING + "/file5": "9",

    OVERLAY1_META + "/rootfs/chld/file0/meta": json.dumps({
        "chmod": 0o644,
        "chownOwner": 0,
        "chownGroup": 0,
        "overlayType": "coW"
    }),

    OVERLAYS + "/overlay1/dir1/fileA": "a",
    OVERLAYS + "/overlay1/dir1/fileB": "b",
    OVERLAYS + "/overlay2/dir1/fileB": "c",
    OVERLAYS + "/overlay2/dir1/fileC": "d",
    OVERLAYS + "/overlay3/dir1/fileD": "e",
    STAGING + "/dir1/fileA": "f",
}

class TestOverlays(t.TestCase):
    maxDiff = 8192

    def setUp(self):
        os.system(f"rm -rf {STAGING} {METADATA} {OVERLAYS}")
        for dir in INIT_DIRS:
            os.system(f"mkdir -p {dir}")
        for file, content in INIT_FILES.items():
            os.system(f"echo -n '{content}' > {file}")

    def _assert_guest_reads(self, file, content):
        cmd = f"cat {file}"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8").strip(), content)

    def _assert_guest_listdir(self, dir, expected_names):
        cmd = f"ls -1 {dir}"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8").strip(), "\n".join(expected_names).strip())

    def _assert_host_listdir(self, dir, expected_names):
        with os.scandir(dir) as it:
            host_list = list(map(lambda x: x.name, it))
            host_list.sort()
            self.assertEqual(host_list, sorted(expected_names))
    
    def _assert_host_reads(self, file, content):
        with open(file, "r") as f:
            self.assertEqual(f.read().strip(), content)

    def test_reads(self):
        expected = {
            STAGING + "/file0": "_",
            STAGING + "/file1": "8",
            STAGING + "/file2": "3",
            STAGING + "/file3": "6",
            STAGING + "/file4": "7",
            STAGING + "/file5": "9",
        }
        for file, content in expected.items():
            self._assert_guest_reads(file, content)

    def test_execve_on_layered_chroot(self):
        ans = c.run_layered_chroot("tests/fixtures/1a-fchown.out")
        stdout = ans.stdout.decode("utf8")
        print("Actual stdout:")
        print(stdout)
        print()
        self.assertEqual(
            stdout,
            (
                "fstatat(/x): owner = 0 group = 0\n"
            ),
        )
        self.assertEqual(ans.returncode, 0)

    def test_reads_metadata_from_overlay(self):
        cmd = f"stat -c '%a %u %g' {STAGING}/file0"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8").strip(), "644 0 0")

    def test_basic_listdir(self):
        self._assert_guest_listdir(STAGING, ["dir1", "file0", "file1", "file2", "file3", "file4", "file5"])
    
    def test_read_after_write(self):
        self._assert_guest_reads(STAGING + "/file2", "3")

        cmd = f"echo -n 'a' > {STAGING}/file2"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_reads(STAGING + "/file2", "a")
        self._assert_host_reads(OVERLAYS + "/overlay1/file2", "1")
        self._assert_host_reads(OVERLAYS + "/overlay2/file2", "3")
        self._assert_host_reads(STAGING + "/file2", "a")

    def test_reads_metadata_after_write(self):
        cmd = f"echo -n 'a' >> {STAGING}/file0"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        cmd = f"stat -c '%a %u %g' {STAGING}/file0"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8").strip(), "644 0 0")
    
    def test_whiteout(self):
        cmd = f"rm -f {STAGING}/file2"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_listdir(STAGING, ["dir1", "file0", "file1", "file3", "file4", "file5"])
        self._assert_host_reads(OVERLAYS + "/overlay1/file2", "1")
        self._assert_host_reads(OVERLAYS + "/overlay2/file2", "3")
        self.assertFalse(os.path.exists(STAGING + "/file2"))

        cmd = f"echo -n 'b' > {STAGING}/file2"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_reads(STAGING + "/file2", "b")
        self._assert_guest_listdir(STAGING, ["dir1", "file0", "file1", "file2", "file3", "file4", "file5"])
        self._assert_host_reads(OVERLAYS + "/overlay1/file2", "1")
        self._assert_host_reads(OVERLAYS + "/overlay2/file2", "3")
        self._assert_host_reads(STAGING + "/file2", "b")

    def test_write_dir(self):
        cmd = f"echo -n 'x' > {STAGING}/dir1/fileX"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_reads(STAGING + "/dir1/fileX", "x")
        self._assert_guest_listdir(STAGING + "/dir1", ["fileA", "fileB", "fileC", "fileD", "fileX"])
        self._assert_host_listdir(OVERLAYS + "/overlay1/dir1", ["fileA", "fileB"])
        self._assert_host_listdir(OVERLAYS + "/overlay2/dir1", ["fileB", "fileC"])
        self._assert_host_listdir(OVERLAYS + "/overlay3/dir1", ["fileD"])
        self.assertTrue(os.path.exists(STAGING + "/dir1"))

        cmd = f"rm -rf {STAGING}/dir1"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_listdir(STAGING, ["file0", "file1", "file2", "file3", "file4", "file5"])
        self._assert_host_listdir(OVERLAYS + "/overlay1/dir1", ["fileA", "fileB"])
        self._assert_host_listdir(OVERLAYS + "/overlay2/dir1", ["fileB", "fileC"])
        self._assert_host_listdir(OVERLAYS + "/overlay3/dir1", ["fileD"])
        self._assert_host_listdir(STAGING, ["file0", "file1", "file2", "file3", "file4", "file5"])
        self.assertFalse(os.path.exists(STAGING + "/dir1"))

        cmd = f"mkdir -p {STAGING}/dir1"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_listdir(STAGING, ["dir1", "file0", "file1", "file2", "file3", "file4", "file5"])
        self._assert_guest_listdir(STAGING + "/dir1", [])
        self._assert_host_listdir(OVERLAYS + "/overlay1/dir1", ["fileA", "fileB"])
        self._assert_host_listdir(OVERLAYS + "/overlay2/dir1", ["fileB", "fileC"])
        self._assert_host_listdir(OVERLAYS + "/overlay3/dir1", ["fileD"])
        self._assert_host_listdir(STAGING, ["dir1", "file0", "file1", "file2", "file3", "file4", "file5"])
        self._assert_host_listdir(STAGING + "/dir1", [])
        self.assertTrue(os.path.exists(STAGING + "/dir1"))