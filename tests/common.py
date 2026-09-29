import os
import subprocess as sub


IS_ANDROID_TERMUX = 'TERMUX_VERSION' in os.environ
STAGING = "tests/fixtures/staging"
METADATA = "tests/fixtures/staging.metadata"


def run(args, **kwargs):
    cmd = " ".join(_get_cmd(**kwargs))
    return os.system(f"{cmd} {args} 1>/dev/null 2>/dev/null")


def run_script(script, timeout=7, stderr=None, env=None, **kwargs):
    cmd = _get_cmd(**kwargs)
    cmd_expr = " ".join(cmd)
    print(f"cmd = {cmd_expr} script = {script.strip()}")
    return sub.run(
        cmd, 
        input=script,
        timeout=timeout,
        stdout=sub.PIPE,
        stderr=stderr or os.sys.stderr,
        env=env or {}
    )

def run_elf(elf_path, timeout=7, stderr=None, env=None, **kwargs):
    """
    Run an ELF binary file without chroot
    """
    if isinstance(elf_path, bytes):
        elf_path = elf_path.decode("utf8")

    cmd = _get_cmd(**kwargs)
    cmd.append("--cmd")
    cmd.append(elf_path)
    cmd_expr = " ".join(cmd)
    print(f"cmd = {cmd_expr}")

    return sub.run(
        cmd, 
        input=b"",
        timeout=timeout,
        stdout=sub.PIPE,
        stderr=stderr or os.sys.stderr,
        env=env or {}
    )


def run_elf_chroot(elf_path, timeout=7, stderr=None, env=None, **kwargs):
    """
    Run an ELF binary file with a proper --chroot
    """
    if isinstance(elf_path, bytes):
        elf_path = elf_path.decode("utf8")

    setup_cmd = f"""
        tests/fixtures/00-setup-chroot.sh '{elf_path}' {STAGING}
    """
    os.system(setup_cmd)

    cmd = _get_cmd(chroot=True, **kwargs)
    if IS_ANDROID_TERMUX:
        cmd.append("--use-native-loader")
    cmd.append("--cmd")
    cmd.append("/executable")
    cmd_expr = " ".join(cmd)
    print(f"cmd = {cmd_expr}")

    return sub.run(
        cmd, 
        input=b"",
        timeout=timeout,
        stdout=sub.PIPE,
        stderr=stderr or os.sys.stderr,
        env=env or {}
    )


def _get_cmd(root=False, rootfs=False, chroot=False):
    args = [
        "target/debug/pocker-runtime",
        "--root" if root else "",
        "--chroot" if chroot else "--rootfs" if rootfs else "",
        STAGING if (chroot or rootfs) else "",
    ]
    return list(filter(bool, args))
