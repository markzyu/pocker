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
            cmd = f"cat {file}"
            ans = c.run_script(cmd.encode(), rootfs=True)
            self.assertEqual(ans.returncode, 0)
            self.assertEqual(ans.stdout.decode("utf8"), content)

    def test_basic_listdir(self):
        cmd = f"ls -1 {STAGING}"
        ans = c.run_script(cmd.encode(), rootfs=True)
        expected = [
            "file0",
            "file1",
            "file2",
            "file3",
            "file4",
            "file5",
        ]
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8"), "\n".join(expected) + "\n")