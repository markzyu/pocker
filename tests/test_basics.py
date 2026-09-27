import common as c
import errno
import os
import subprocess
import unittest as t


class TestBasics(t.TestCase):
    def setUp(self):
        pass

    def test_reports_success(self):
        self.assertEqual(c.run("--cmd echo"), 0)

    def test_reports_failure(self):
        self.assertNotEqual(c.run("--cmd rm"), 0)

    def test_reports_exact_errcode(self):
        for val in (0, 1, 254, 255):
            ans = c.run_script(f"exit {val}".encode())
            self.assertEqual(ans.returncode, val)

        if os.sys.platform.startswith("linux"):
            # Linux exitcode is 0-255. Exit 256 should return 0
            ans = c.run_script(b"exit 256")
            self.assertEqual(ans.returncode, 0)
            # Linux exitcode is 0-255. Exit 257 should return 1
            ans = c.run_script(b"exit 257")
            self.assertEqual(ans.returncode, 1)

    def test_run_man(self):
        ans = c.run_script(b"man bash | head -n 1")
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout.split(b"(")[0].lower(), b"bash")

    def test_run_shell_script_with_spaces_in_shebang(self):
        ans = c.run_elf(b"./tests/fixtures/02-script-with-spaces-in-shebang.sh")
        self.assertEqual(ans.returncode, 0)
        self.assertEqual(ans.stdout, b"TEST\n")

    def test_run_shell_script_with_invalid_shebang(self):
        ans = c.run_elf(b"./tests/fixtures/03-script-invalid-shebang.sh", stderr=subprocess.PIPE)
        self.assertNotEqual(ans.returncode, 0)
        self.assertIn(b"because of invalid shebang: \"/bin/sh -a -b -c\"", ans.stderr)

    def test_wait4_is_restarted_if_child_is_stopped(self):
        for run_method in (c.run_script, c.run_elf_chroot):
            ans = run_method(b"./tests/fixtures/04-wait4-restarts.out")
            self.assertNotIn(b"waitpid failure", ans.stdout)
            self.assertNotIn(b"is exit: 0 is stop: 1 exit code:", ans.stdout)
            self.assertIn(b"is exit: 1 is stop: 0 exit code: 1", ans.stdout)

    def test_wait4_details(self):
        for run_method in (c.run_script, c.run_elf_chroot):
            ans = run_method(b"./tests/fixtures/06-wait4-details.out")
            EINTR = str(errno.EINTR).encode()
            self.assertIn(b"case1, retval 0, status 0", ans.stdout)
            self.assertIn(b"case2, retval -1, errno " + EINTR + b", status 0", ans.stdout)
            self.assertIn(b"case3, retval pid, status 256", ans.stdout)

    def test_vfork(self):
        for run_method in (c.run_script, c.run_elf_chroot):
            for test_name in ("08-vfork.out", "09-clone_vfork.out"):
                ans = run_method(f"./tests/fixtures/{test_name}".encode())
                self.assertIn(b"result: 22 errno: 0", ans.stdout)
                self.assertNotIn(b"TracerPid:\t0", ans.stdout)

    def test_run_id_as_root(self):
        ans = c.run_script(b"id", root=True)
        self.assertEqual(ans.returncode, 0)

        parts = ans.stdout.split(b" ")
        self.assertEqual(parts[0], b"uid=0(root)")
        self.assertEqual(parts[1], b"gid=0(root)")

    def test_setuid_neg1(self):
        for run_method in (c.run_script, c.run_elf_chroot):
            ans = run_method(b"./tests/fixtures/07-perms-setuid-neg1.out", root=True)
            EINVAL = str(errno.EINVAL).encode()
            self.assertIn(b"result: -1 errno: " + EINVAL, ans.stdout)
    
    @t.skip('Modern linux can set ping permission per binary, which causes this to fail')
    def test_ping_if_ping_is_available(self):
        ping_available = os.system("echo Making sure ping is available...; ping -c 4 localhost")
        if ping_available != 0:
            return
        
        ans = c.run_script(b"ping -c 4 localhost")
        self.assertEqual(ans.returncode, 0)
