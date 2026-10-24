from common import METADATA, STAGING, OVERLAYS
import common as c
import errno
import json
import os
import subprocess
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
    OVERLAY1_META + "/rootfs/chld/link0",
    OVERLAY1_META + "/links",
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

    OVERLAY1_META + "/rootfs/chld/link0/meta": json.dumps({
        "chmod": 0o644,
        "chownOwner": 0,
        "chownGroup": 0,
        "overlayType": "coW"
    }),

    OVERLAY1_META + "/links/id0": "content0",
    OVERLAY1_META + "/links/id0.json": json.dumps({
        "hardlinkCounter": 2,
    }),
}

INIT_LINKS = {
    OVERLAYS + "/overlay1/link0": "file1",
    OVERLAYS + "/overlay1/link1": "file1",
    OVERLAYS + "/overlay1/link2": "file1",
    OVERLAYS + "/overlay2/link1": "file0",
    STAGING + "/link0": "file2",

    OVERLAYS + "/overlay1/dir1/linkA": "../..",
    OVERLAYS + "/overlay1/dir1/linkB": "..",
    OVERLAYS + "/overlay2/dir1/linkB": "../..",
    STAGING + "/dir1/linkA": "..",

    OVERLAYS + "/overlay1/hardlink0": os.path.abspath(OVERLAY1_META + "/links/id0"),
}

class TestOverlaysWithLinks(t.TestCase):
    maxDiff = 8192

    def setUp(self):
        os.system(f"rm -rf {STAGING} {METADATA} {OVERLAYS}")
        for dir in INIT_DIRS:
            os.system(f"mkdir -p {dir}")
        for link, content in INIT_FILES.items():
            os.system(f"echo -n '{content}' > {link}")
        for link, target in INIT_LINKS.items():
            os.system(f"ln -s {target} {link}")

    def _assert_guest_readlink(self, link, target):
        cmd = f"readlink {link}"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8").strip(), target)

    def _assert_guest_hardlink(self, link, counter):
        cmd = f"stat -c '%h' {link}"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8").strip(), str(counter))

    def _assert_guest_reads(self, link, content):
        cmd = f"cat {link}"
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

    def _assert_host_reads(self, link, content):
        with open(link, "r") as f:
            self.assertEqual(f.read().strip(), content)

    def _assert_host_readlink(self, link, target):
        self.assertEqual(target, os.readlink(link))

    def test_reads(self):
        expected = {
            STAGING + "/link0": "file2",
            STAGING + "/link1": "file0",
            STAGING + "/link2": "file1",
            STAGING + "/dir1/linkA": "..",
            STAGING + "/dir1/linkB": "../..",
        }
        for link, content in expected.items():
            self._assert_guest_readlink(link, content)

        self._assert_guest_hardlink(STAGING + "/hardlink0", 2)

    def test_writes_symlink(self):
        cmd = f"ln -s -f ../../.. {STAGING}/dir1/linkA/dir1/linkB"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_readlink(STAGING + "/dir1/linkB", "../../..")
        self._assert_host_readlink(OVERLAYS + "/overlay1/dir1/linkB", "..")
        self._assert_host_readlink(OVERLAYS + "/overlay2/dir1/linkB", "../..")

    def test_read_hardlink(self):
        self._assert_guest_reads(STAGING + "/hardlink0", "content0")
        self._assert_host_reads(STAGING + "/hardlink0", "")

    def test_read_hardlink_after_write(self):
        cmd = f"echo -n 'content1' > {STAGING}/hardlink0"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_reads(STAGING + "/hardlink0", "content1")
        self._assert_host_reads(STAGING + "/hardlink0", "content1")
        self._assert_host_reads(OVERLAY1_META + "/links/id0", "content0")

        # The file should no longer be a hardlink.
        self._assert_guest_hardlink(STAGING + "/hardlink0", 1)

    def test_whiteout_hardlink(self):
        cmd = f"rm -f {STAGING}/hardlink0"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_listdir(STAGING, ["dir1", "link0", "link1", "link2"])
        self._assert_host_listdir(STAGING, ["dir1", "link0", "link1", "link2"])
        self._assert_host_reads(OVERLAY1_META + "/links/id0", "content0")