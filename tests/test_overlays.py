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

INIT_DIRS = [
    STAGING,
    METADATA,
    OVERLAYS + "/overlay1",
    OVERLAYS + "/overlay2",
    OVERLAYS + "/overlay3",
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

    def test_basic_listdir(self):
        self._assert_guest_listdir(STAGING, ["file0", "file1", "file2", "file3", "file4", "file5"])
    
    def test_read_after_write(self):
        self._assert_guest_reads(STAGING + "/file2", "3")

        cmd = f"echo -n 'a' > {STAGING}/file2"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_reads(STAGING + "/file2", "a")
        self._assert_host_reads(OVERLAYS + "/overlay1/file2", "1")
        self._assert_host_reads(OVERLAYS + "/overlay2/file2", "3")
        self._assert_host_reads(STAGING + "/file2", "a")
    
    def test_whiteout(self):
        cmd = f"rm -f {STAGING}/file2"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_listdir(STAGING, ["file0", "file1", "file3", "file4", "file5"])
        self._assert_host_reads(OVERLAYS + "/overlay1/file2", "1")
        self._assert_host_reads(OVERLAYS + "/overlay2/file2", "3")
        self.assertFalse(os.path.exists(STAGING + "/file2"))

        cmd = f"echo -n 'b' > {STAGING}/file2"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_reads(STAGING + "/file2", "b")
        self._assert_guest_listdir(STAGING, ["file0", "file1", "file2", "file3", "file4", "file5"])
        self._assert_host_reads(OVERLAYS + "/overlay1/file2", "1")
        self._assert_host_reads(OVERLAYS + "/overlay2/file2", "3")
        self._assert_host_reads(STAGING + "/file2", "b")