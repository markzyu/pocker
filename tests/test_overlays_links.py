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
OVERLAY2_META = OVERLAYS + "/overlay2.metadata"

INIT_DIRS = [
    STAGING,
    METADATA,
    OVERLAYS + "/overlay1",
    OVERLAYS + "/overlay2",
    OVERLAYS + "/overlay3",
    OVERLAYS + "/overlay1/dir1",
    OVERLAYS + "/overlay2/dir1",
    OVERLAYS + "/overlay3/dir1",
    OVERLAY2_META + "/rootfs/chld/link1",
    OVERLAY1_META + "/rootfs/chld/hardlink0",
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

    OVERLAY2_META + "/rootfs/chld/link1/meta": json.dumps({
        "chmod": 0o644,
        "chownOwner": 0,
        "chownGroup": 0,
        "overlayType": "coW"
    }),

    OVERLAY1_META + "/links/id0": "content0",
    OVERLAY1_META + "/links/id0.json": json.dumps({
        "chmod": 0o644,
        "chownOwner": 0,
        "chownGroup": 0,
        "hardlinkCounter": 2,
    }),

    # This data should be ignored.
    OVERLAY1_META + "/rootfs/chld/hardlink0/meta": json.dumps({
        "chmod": 0o640,
        "chownOwner": 0,
        "chownGroup": 0,
        "hardlinkCounter": 4,
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

    def _assert_host_hardlink(self, link, counter):
        with open(link + ".json", "r") as f:
            data = json.load(f)
            self.assertEqual(data["hardlinkCounter"], counter)

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

        self._assert_guest_reads(STAGING + "/hardlink0", "content0")
        self._assert_guest_hardlink(STAGING + "/hardlink0", 2)

    def test_read_symlink_metadata_from_overlay(self):
        cmd = f"stat -c '%a %u %g' {STAGING}/link1"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8").strip(), "644 0 0")

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

    def test_read_hardlink_metadata_from_overlay(self):
        cmd = f"stat -c '%a %u %g' {STAGING}/hardlink0"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8").strip(), "644 0 0")

    def test_read_hardlink_after_write(self):
        cmd = f"echo -n 'content1' > {STAGING}/hardlink0"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_reads(STAGING + "/hardlink0", "content1")
        self._assert_host_reads(STAGING + "/hardlink0", "content1")
        self._assert_host_reads(OVERLAY1_META + "/links/id0", "content0")

        # The file should keep the same metadata from overlay
        cmd = f"stat -c '%a %u %g' {STAGING}/hardlink0"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.decode("utf8").strip(), "644 0 0")

        # The file should no longer be a hardlink.
        self._assert_guest_hardlink(STAGING + "/hardlink0", 1)

    def test_whiteout_hardlink(self):
        cmd = f"rm -f {STAGING}/hardlink0"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        self._assert_guest_listdir(STAGING, ["dir1", "link0", "link1", "link2"])
        self._assert_host_listdir(STAGING, ["dir1", "link0", "link1", "link2"])
        self._assert_host_reads(OVERLAY1_META + "/links/id0", "content0")

    def test_new_hardlink_of_layer(self):
        """
        New hardlinks of a file in a readonly layer should copy the original file into
        rootfs.metadata/links, and should not share the same counter.
        """
        cmd = f"ln -f {STAGING}/hardlink0 {STAGING}/hardlink1"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        cmd = f"ln -f {STAGING}/hardlink0 {STAGING}/hardlink2"
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)

        main_links_dir = os.path.abspath(METADATA + "/links")
        self.assertTrue(os.readlink(STAGING + "/hardlink0").startswith(main_links_dir))
        self.assertTrue(os.readlink(STAGING + "/hardlink1").startswith(main_links_dir))
        self.assertTrue(os.readlink(STAGING + "/hardlink2").startswith(main_links_dir))

        self._assert_guest_hardlink(STAGING + "/hardlink0", 3)
        self._assert_guest_hardlink(STAGING + "/hardlink1", 3)
        self._assert_guest_hardlink(STAGING + "/hardlink2", 3)
        self._assert_host_hardlink(OVERLAY1_META + "/links/id0", 2)