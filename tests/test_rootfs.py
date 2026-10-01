from common import METADATA, STAGING
import common as c
import errno
import json
import os
import subprocess
import tarfile
import time
import unittest as t


class TestRootFs(t.TestCase):
    maxDiff = 8192

    def setUp(self):
        init_ok = os.system(
            f"""
            pwd >&2;
            set -e
            echo "[INITIALIZING TESTS]" >&2
            rm -rf {STAGING}; 
            rm -rf {METADATA}; 
            mkdir -p {STAGING}; 
            cd {STAGING};
            rm -f ../result.tar;
            echo "[INITIALIZED TESTS]" >&2
            """
        )
        self.assertEqual(init_ok, 0)

    def _setup_untar(self, tar_name):
        init_ok = os.system(
            f"""
            echo "[CREATING STAGING FROM TAR]" >&2
            cd {STAGING} && tar xf ../{tar_name};
            if [ $? -ne 0 ]; then
                echo "[ERROR CREATING STAGING FROM TAR]" >&2
                exit $?
            fi
            echo "[CREATED STAGING FROM TAR]" >&2
            """
        )
        self.assertEqual(init_ok, 0)

    def _setup_untar_in_container(self, tar_name, **kwargs):
        ans = c.run_script(
            f"""
            echo "[POCKER] [CREATING STAGING FROM TAR]" >&2
            cd {STAGING} && tar xpf ../{tar_name};
            if [ $? -ne 0 ]; then
                echo "[POCKER] [ERROR CREATING STAGING FROM TAR]" >&2
                exit $?
            fi
            echo "[POCKER] [CREATED STAGING FROM TAR]" >&2
            """.encode(),
            rootfs=True,
            root=True,
            **kwargs,
        )
        self.assertEqual(ans.returncode, 0)

    def _create_tar_from_container(self, dir, tar_name, **kwargs):
        # In addition to using pocker-runtime, we must create the tar in deterministic order
        ans = c.run_script(
            f"""
            echo "[POCKER] [CREATING TAR]" >&2
            umask 0077 && cd {dir} && rm -f ../{tar_name} && (
                find . | sort | tar cf ../{tar_name} --no-recursion -T -
            )
            if [ $? -ne 0 ]; then
                echo "[POCKER] [ERROR CREATING STAGING FROM TAR]" >&2
                exit $?
            fi
            echo "[POCKER] [CREATED TAR]" >&2
            """.encode(),
            rootfs=True,
            env={"RUST_LOG": "TRACE", "RUST_LOG_BLOCKING": "1"},
            **kwargs,
        )
        self.assertEqual(ans.returncode, 0)

    def _create_tar_from_host_os(self, dir, tar_name):
        cmd = f"""
        echo "[ASSERT] [TARRING DIR FOR COMPARISON] {dir}" >&2
        ls -l {STAGING}
        ls -l {METADATA}
        cd {dir} && rm -f ../{tar_name} && tar cf ../{tar_name} .
        if [ $? -ne 0 ]; then
            echo "[ASSERT] [ERROR TARRING DIR FOR COMPARISON]" >&2
            exit $?
        fi
        echo "[ASSERT] [TARRED DIR FOR COMPARISON]" >&2
        """
        ok = os.system(cmd)
        self.assertEqual(ok, 0)

    """ This assumes that there is only one hardlink in the rootfs """
    def _read_hardlink_counter(self):
        links_dir = os.path.join(METADATA, "links")
        link_metadata_files = [
            path for path in os.listdir(links_dir)
            if path.endswith(".json")
        ]
        self.assertEqual(len(link_metadata_files), 1)
        with open(os.path.join(links_dir, link_metadata_files[0])) as f:
            link_metadata = json.load(f)
        return link_metadata["hardlinkCounter"]

    def compare_tar_with_dir(self, dir, expected_name, ignore_perms=False):
        actual_name = "result.tar"
        if ignore_perms:
            self._create_tar_from_host_os(dir, actual_name)
        else:
            self._create_tar_from_container(dir, actual_name)

        if os.environ.get("UPDATE_TARS") == "1":
            os.rename(f"tests/fixtures/{actual_name}", f"tests/fixtures/{expected_name}")
            return

        tar_info_fn = _tar_info_minimal_no_perms if ignore_perms else _tar_info_minimal

        with tarfile.open(f"tests/fixtures/{expected_name}") as expect_tar:
            expect_val = _sort_tar_info(map(tar_info_fn, expect_tar.getmembers()))
        with tarfile.open(f"tests/fixtures/{actual_name}") as actual_tar:
            actual_val = _sort_tar_info(map(tar_info_fn, actual_tar.getmembers()))
        self.assertEqual(expect_val, actual_val)

    def test_rootfs_creates_metadata(self):
        self._setup_untar_in_container("01-rootfs-metadata-mounted.tar")
        self.compare_tar_with_dir(METADATA, "01-rootfs-metadata-raw.tar", ignore_perms=True)
        self.compare_tar_with_dir(STAGING, "01-rootfs-metadata-mounted.tar")

    def test_rm_rf_after_rootfs_creates_metadata(self):
        """
        Removing an entire rootfs should also remove the metadata
        """
        self.test_rootfs_creates_metadata()

        cmd = f"""
        set -x;
        rm -rf {STAGING};
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertFalse(os.path.exists(STAGING))
        self.assertFalse(os.path.exists(METADATA + "/rootfs"))

    def test_rmdir_deletes_untracked_metadata_files(self):
        """
        Delete the metadata of direct children of a folder, even
        if that metadata was created by mistake...

        (This is useful for now, but should be deprecated once we
        cover all unlink/rmdir syscalls)
        """
        self.test_rootfs_creates_metadata()
        timestamp = int(time.time())
        os.system(f"touch {STAGING}/.blahblahblah-{timestamp}")

        cmd = f"""
        set -x;
        rm -rf {STAGING};
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertFalse(os.path.exists(STAGING))
        self.assertFalse(os.path.exists(METADATA + "/rootfs"))

    def test_rootfs_basic_hardlinks(self):
        cmd = f"""
        set -x;
        touch {STAGING}/a;
        ln {STAGING}/a {STAGING}/b;
        stat {STAGING}/a | head -n 2
        cat {STAGING}/a
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertIn(b"regular empty file", ans.stdout)
        self.assertEqual(self._read_hardlink_counter(), 2)
        self.compare_tar_with_dir(STAGING, "1c-rootfs-hardlinks-basic.tar")

    def test_rootfs_singular_hardlink(self):
        cmd = f"""
        set -x;
        touch {STAGING}/a;
        ln {STAGING}/a {STAGING}/b;
        rm {STAGING}/a;
        stat {STAGING}/b | head -n 2
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertIn(b"regular empty file", ans.stdout)
        self.assertEqual(self._read_hardlink_counter(), 1)
        self.compare_tar_with_dir(STAGING, "1c-rootfs-hardlinks-singular.tar")

    def test_rootfs_hardlink_removal(self):
        cmd = f"""
        set -x;
        touch {STAGING}/a;
        ln {STAGING}/a {STAGING}/b;
        rm {STAGING}/a {STAGING}/b;
        ls -l {STAGING}
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertIn(b"total 0", ans.stdout)
        self.compare_tar_with_dir(METADATA, "1c-rootfs-hardlinks-empty-metadata.tar", ignore_perms=True)
        self.compare_tar_with_dir(STAGING, "1c-rootfs-hardlinks-empty-staging.tar")

    def test_rootfs_hardlink_rename(self):
        cmd = f"""
        set -x;
        touch {STAGING}/a;
        ln {STAGING}/a {STAGING}/b;
        mv {STAGING}/a {STAGING}/c;
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(self._read_hardlink_counter(), 2)
        self.compare_tar_with_dir(STAGING, "1c-rootfs-hardlinks-rename.tar")

    def test_rootfs_hardlink_copy(self):
        cmd = f"""
        set -x;
        touch {STAGING}/a;
        ln {STAGING}/a {STAGING}/b;
        cp {STAGING}/a {STAGING}/c;
        """
        ans = c.run_script(cmd.encode(), rootfs=True)
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(self._read_hardlink_counter(), 3)
        self.compare_tar_with_dir(STAGING, "1c-rootfs-hardlinks-copy.tar")

    def test_chroot_symlinks(self):
        os.system(f"ls -l {STAGING}")
        ans = c.run_elf_chroot("tests/fixtures/05-symlinks.out")
        stdout = ans.stdout.decode("utf8")
        print("Actual stdout:")
        print(stdout)
        print()
        self.assertEqual(
            stdout,
            (
                "created symlinks\n"
                "/link -> /link\n"
                "/a -> /c\n"
                "/y -> /x\n"
                f"readlink(/x) = -1 errno = {errno.EINVAL} \n"
                f"open(/link) = -1 errno = {errno.ELOOP}\n"
                f"open(/a) = -1 errno = {errno.ELOOP}\n"
                f"open(/y) = 0 errno = {errno.ELOOP}\n"
                f"open(/x) = 0 errno = {errno.ELOOP}\n"
                "/z -> /x\n"
                f"fstatat(/link) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/a) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/b) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/c) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/y) = -1 errno = {errno.ENOENT}\n"
                f"fstatat(/x) = 0 errno = {errno.ENOENT}\n"
                f"fstatat(/z) = -1 errno = {errno.ENOENT}\n"
            ),
        )
        self.assertEqual(ans.returncode, 0)
    
    def test_chroot_fchown(self):
        os.system(f"ls -l {STAGING}")
        ans = c.run_elf_chroot("tests/fixtures/1a-fchown.out")
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


def _sort_tar_info(obj):
    return sorted(obj, key=lambda x: x["name"])


def _tar_info_minimal(obj):
    return {
        "name": obj.name,
        "size": obj.size,
        "mode": obj.mode,
        "type": obj.type,
        "linkname": obj.linkname,
    }

def _tar_info_minimal_no_perms(obj):
    return {
        "name": obj.name,
        "size": obj.size,
        "type": obj.type,
        "linkname": obj.linkname,
    }


def _tar_info(obj):
    return {
        "mtime": obj.mtime,
        "uid": obj.uid,
        "gid": obj.gid,
        "uname": obj.uname,
        "gname": obj.gname,
        "pax": obj.pax_headers,
        **_tar_info_minimal(obj),
    }
