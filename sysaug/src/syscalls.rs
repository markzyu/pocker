// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

#![allow(non_snake_case)]
#![allow(unused_macros)]

use crate::common::{
    Augments, DelType, NO_MOD_SYSCALL, PermType, SyscallInfo, default_syscall_info,
};

/// This limits how many syscalls can be ptrace-eligible.
const MAX_RAW_SYSCALL_INFOS: usize = 512;

/// We use a raw array to index syscalls. This defines the max length of the array.
const MAX_SYSCALL_NUMBER: usize = 1024;

macro_rules! define_syscall {
    ($name:expr, $augment:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for ptrace-eligible syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: $augment,
            name: stringify!($name),
            num: $name,
            ..default_syscall_info()
        });
    };
}

macro_rules! define_seccomp_syscall {
    ($name:expr, $seccomp_position:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Seccomp,
            name: stringify!($name),
            num: $name,
            seccomp_position: Some($seccomp_position),
            ..default_syscall_info()
        });
    };
}

macro_rules! define_fileperms_syscall {
    ($name:expr, $perm_type:expr, $perms_pos:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            sets_file_perms: Some($perm_type),
            file_perms_position: Some($perms_pos),
            ..default_syscall_info()
        });
    };
}

macro_rules! define_perms_syscall {
    ($name:expr, $is_setter:expr, $res_bits:expr, $resf_bit:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Perms,
            name: stringify!($name),
            num: $name,
            is_setter: $is_setter,
            res_bits: $res_bits,
            resf_bit: $resf_bit,
            ..default_syscall_info()
        });
    };
}

macro_rules! define_paths_syscall {
    ($name:expr, $path_positions:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            getdents_bits: None,
            ..default_syscall_info()
        });
    };
}

macro_rules! define_paths_deletion_syscall {
    ($name:expr, $path_positions:expr, $type:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            getdents_bits: None,
            deletion_type: Some($type),
            ..default_syscall_info()
        });
    };
}

macro_rules! define_paths_fileperms_syscall {
    ($name:expr, $path_positions:expr, $perm_type:expr, $perms_pos:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            getdents_bits: None,
            sets_file_perms: Some($perm_type),
            file_perms_position: Some($perms_pos),
            ..default_syscall_info()
        });
    };
}

// In this version, all paths share the same dirfd
macro_rules! define_dirfd_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            dirfd_position: Some($dirfd_position),
            getdents_bits: None,
            ..default_syscall_info()
        });
    };
}

// In this version, there is no file path or parent dirfd. The fd specifies the file itself
macro_rules! define_filefd_syscall {
    ($name:expr, $filefd_position:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            filefd_position: Some($filefd_position),
            getdents_bits: None,
            ..default_syscall_info()
        });
    };
}

// In this version, the dirfd for each path is the argument immediately preceding it.
macro_rules! define_dirfd2_syscall {
    ($name:expr, $path_positions:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            dirfd_precedes_path: true,
            dirfd_position: None,
            getdents_bits: None,
            ..default_syscall_info()
        });
    };
}

macro_rules! define_dirfd_deletion_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $type:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            dirfd_position: Some($dirfd_position),
            getdents_bits: None,
            deletion_type: Some($type),
            ..default_syscall_info()
        });
    };
}

macro_rules! define_dirfd_fileperms_syscall {
    ($name:expr, $path_positions:expr, $dirfd_position:expr, $perm_type:expr, $perms_pos:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: $path_positions,
            dirfd_position: Some($dirfd_position),
            getdents_bits: None,
            sets_file_perms: Some($perm_type),
            file_perms_position: Some($perms_pos),
            ..default_syscall_info()
        });
    };
}

macro_rules! define_getdents_syscall {
    ($name:expr, $getdents_bits:expr, $iter:ident, $next:ident) => {
        $next += 1;
        if $next >= MAX_RAW_SYSCALL_INFOS {
            panic!("No more space for syscalls");
        }
        if ($name as usize) == NO_MOD_SYSCALL {
            panic!("Syscall list should not include NO_MOD_SYSCALL");
        }
        $iter[$next] = Some(SyscallInfo {
            augment: Augments::Paths,
            name: stringify!($name),
            num: $name,
            path_positions: 0,
            getdents_bits: Some($getdents_bits),
            ..default_syscall_info()
        });
    };
}

// ----------------- DEFINE ALL KNOWN SYSCALLS ------------------

pub const RAW_SYSCALL_INFOS: [Option<SyscallInfo>; MAX_RAW_SYSCALL_INFOS] = {
    let mut iter = [const { None }; MAX_RAW_SYSCALL_INFOS];
    let mut next: usize = 0;

    define_syscall!(libc::SYS_clone, Augments::Clone, iter, next);
    define_syscall!(libc::SYS_wait4, Augments::Waitpid, iter, next);
    define_perms_syscall!(libc::SYS_getuid, false, 0, Some(4), iter, next);
    define_perms_syscall!(libc::SYS_geteuid, false, 0, Some(5), iter, next);
    define_perms_syscall!(libc::SYS_getgid, false, 0, Some(0), iter, next);
    define_perms_syscall!(libc::SYS_getegid, false, 0, Some(1), iter, next);
    define_perms_syscall!(libc::SYS_getgroups, false, 0, None, iter, next);
    define_perms_syscall!(libc::SYS_setuid, true, 0, Some(4), iter, next);
    define_perms_syscall!(libc::SYS_setgid, true, 0, Some(0), iter, next);
    define_perms_syscall!(libc::SYS_setgroups, true, 0, None, iter, next);
    define_perms_syscall!(libc::SYS_setregid, true, 3, None, iter, next);
    define_perms_syscall!(libc::SYS_setreuid, true, 19, None, iter, next);
    define_perms_syscall!(libc::SYS_setresgid, true, 7, None, iter, next);
    define_perms_syscall!(libc::SYS_setresuid, true, 23, None, iter, next);
    define_perms_syscall!(libc::SYS_setfsgid, true, 0, Some(3), iter, next);
    define_perms_syscall!(libc::SYS_setfsuid, true, 0, Some(7), iter, next);

    #[cfg(any(target_arch = "arm", target_arch = "x86"))]
    {
        define_perms_syscall!(libc::SYS_getuid32, false, 0, Some(4), iter, next);
        define_perms_syscall!(libc::SYS_geteuid32, false, 0, Some(5), iter, next);
        define_perms_syscall!(libc::SYS_getgid32, false, 0, Some(0), iter, next);
        define_perms_syscall!(libc::SYS_getegid32, false, 0, Some(1), iter, next);
        define_perms_syscall!(libc::SYS_getgroups32, false, 0, None, iter, next);
        define_perms_syscall!(libc::SYS_setuid32, true, 0, Some(4), iter, next);
        define_perms_syscall!(libc::SYS_setgid32, true, 0, Some(0), iter, next);
        define_perms_syscall!(libc::SYS_setgroups32, true, 0, None, iter, next);
        define_perms_syscall!(libc::SYS_setregid32, true, 3, None, iter, next);
        define_perms_syscall!(libc::SYS_setreuid32, true, 19, None, iter, next);
        define_perms_syscall!(libc::SYS_setresgid32, true, 7, None, iter, next);
        define_perms_syscall!(libc::SYS_setresuid32, true, 23, None, iter, next);
        define_perms_syscall!(libc::SYS_setfsgid32, true, 0, Some(3), iter, next);
        define_perms_syscall!(libc::SYS_setfsuid32, true, 0, Some(7), iter, next);
    }

    define_seccomp_syscall!(libc::SYS_prctl, 1, iter, next);
    define_seccomp_syscall!(libc::SYS_seccomp, 0, iter, next);

    define_paths_syscall!(libc::SYS_acct, 1, iter, next);
    define_paths_syscall!(libc::SYS_chdir, 1, iter, next);
    define_paths_syscall!(libc::SYS_chroot, 1, iter, next);
    define_paths_syscall!(libc::SYS_getxattr, 1, iter, next);
    define_paths_syscall!(libc::SYS_listxattr, 1, iter, next);
    define_paths_syscall!(libc::SYS_removexattr, 1, iter, next);
    define_paths_syscall!(libc::SYS_setxattr, 1, iter, next);
    define_paths_syscall!(libc::SYS_swapoff, 1, iter, next);
    define_paths_syscall!(libc::SYS_swapon, 1, iter, next);
    define_paths_syscall!(libc::SYS_umount2, 1, iter, next);
    define_syscall!(libc::SYS_execve, Augments::Exec, iter, next);

    define_dirfd_syscall!(libc::SYS_name_to_handle_at, 2, 0, iter, next);
    define_dirfd_syscall!(libc::SYS_faccessat, 2, 0, iter, next);
    define_dirfd2_syscall!(libc::SYS_linkat, 10, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.creates_hardlink = true;
    }

    define_dirfd_fileperms_syscall!(libc::SYS_fchmodat, 2, 0, PermType::Chmod, 2, iter, next);
    define_dirfd_fileperms_syscall!(libc::SYS_fchownat, 2, 0, PermType::Chown, 2, iter, next);
    define_dirfd_fileperms_syscall!(libc::SYS_mkdirat, 2, 0, PermType::Chmod, 2, iter, next);
    define_dirfd_fileperms_syscall!(libc::SYS_mknodat, 2, 0, PermType::Chmod, 2, iter, next);

    define_dirfd_syscall!(libc::SYS_openat, 2, 0, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.sets_file_perms = Some(PermType::ChmodOnCreation);
        val.file_perms_position = Some(3);
        val.flags = Some(2);
    }

    define_dirfd_syscall!(libc::SYS_readlinkat, 2, 0, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_dirfd2_syscall!(libc::SYS_renameat, 10, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_dirfd2_syscall!(libc::SYS_renameat2, 10, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_dirfd_syscall!(libc::SYS_symlinkat, 4, 1, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
        val.creates_symlink = true;
    }

    define_dirfd_deletion_syscall!(libc::SYS_unlinkat, 2, 0, DelType::File, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_paths_syscall!(libc::SYS_lgetxattr, 1, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    define_paths_syscall!(libc::SYS_llistxattr, 1, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.dont_follow_symlink = true;
    }

    #[cfg(not(target_arch = "aarch64"))]
    define_filefd_syscall!(libc::SYS_fstat, 0, iter, next);
    #[cfg(target_arch = "aarch64")]
    let libc__SYS_fstat: i64 = 80;
    #[cfg(target_arch = "aarch64")]
    define_filefd_syscall!(libc__SYS_fstat, 0, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.stat_legacy_buf_position = Some(1);
    }

    define_dirfd_syscall!(libc::SYS_statx, 2, 0, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.flags = Some(2);
        val.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
        val.statx_buf_position = Some(4);
    }

    #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
    {
        define_paths_syscall!(libc::SYS_truncate, 1, iter, next);
        define_paths_syscall!(libc::SYS_statfs, 1, iter, next);
    }

    define_dirfd_syscall!(libc::SYS_utimensat, 2, 0, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.flags = Some(3);
        val.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
    }

    define_getdents_syscall!(libc::SYS_getdents64, 64, iter, next);

    define_fileperms_syscall!(libc::SYS_fchmod, PermType::Chmod, 1, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.filefd_position = Some(0);
    }

    define_fileperms_syscall!(libc::SYS_fchown, PermType::Chown, 1, iter, next);
    if let Some(val) = iter[next].as_mut() {
        val.filefd_position = Some(0);
    }

    #[cfg(target_arch = "arm")]
    {
        define_paths_syscall!(libc::SYS_chown32, 1, iter, next);
        define_paths_syscall!(libc::SYS_stat64, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.stat64_buf_position = Some(1);
        }

        define_filefd_syscall!(libc::SYS_fstat64, 0, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.stat64_buf_position = Some(1);
        }

        define_dirfd_syscall!(libc::SYS_fstatat64, 2, 0, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.flags = Some(3);
            val.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
            val.stat64_buf_position = Some(2);
        }

        define_paths_syscall!(libc::SYS_statfs64, 1, iter, next);
        define_paths_syscall!(libc::SYS_truncate64, 1, iter, next);

        define_paths_syscall!(libc::SYS_lchown32, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_syscall!(libc::SYS_lstat64, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
            val.stat64_buf_position = Some(1);
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        define_dirfd_syscall!(libc::SYS_faccessat2, 2, 0, iter, next);
        define_paths_syscall!(libc::SYS_rename, 3, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_syscall!(libc::SYS_utime, 1, iter, next);
        define_getdents_syscall!(libc::SYS_getdents, 32, iter, next);

        // New System call in Linux v6.6: fchmodat2
        let libc__SYS_fchmodat2: i64 = 452;
        define_dirfd_fileperms_syscall!(libc__SYS_fchmodat2, 2, 0, PermType::Chmod, 2, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.flags = Some(3);
        }
    }

    #[cfg(target_arch = "x86_64")]
    let libc__SYS_newfstatat: i64 = libc::SYS_newfstatat;

    #[cfg(target_arch = "aarch64")]
    let libc__SYS_newfstatat: i64 = 79;

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        define_dirfd_syscall!(libc__SYS_newfstatat, 2, 0, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.flags = Some(3);
            val.flag_dont_follow_symlink = Some(libc::AT_SYMLINK_NOFOLLOW as usize);
            val.stat_buf_position = Some(2);
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "arm"))]
    {
        define_paths_syscall!(libc::SYS_access, 1, iter, next);
        define_paths_fileperms_syscall!(libc::SYS_chmod, 1, PermType::Chmod, 1, iter, next);
        define_paths_fileperms_syscall!(libc::SYS_chown, 1, PermType::Chown, 1, iter, next);
        define_paths_fileperms_syscall!(libc::SYS_mknod, 1, PermType::Chown, 1, iter, next);
        define_paths_fileperms_syscall!(libc::SYS_creat, 1, PermType::Chown, 1, iter, next);
        define_paths_syscall!(libc::SYS_uselib, 1, iter, next);
        define_paths_syscall!(libc::SYS_utimes, 1, iter, next);
        define_dirfd_syscall!(libc::SYS_futimesat, 2, 0, iter, next);
        define_paths_syscall!(libc::SYS_link, 3, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.creates_hardlink = true;
        }

        define_paths_syscall!(libc::SYS_open, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.sets_file_perms = Some(PermType::ChmodOnCreation);
            val.file_perms_position = Some(2);
            val.flags = Some(1);
        }

        define_paths_syscall!(libc::SYS_readlink, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_fileperms_syscall!(libc::SYS_lchown, 1, PermType::Chown, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_syscall!(libc::SYS_stat, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
            val.stat_legacy_buf_position = Some(1);
        }

        define_paths_syscall!(libc::SYS_lstat, 1, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
            val.stat_legacy_buf_position = Some(1);
        }

        define_paths_syscall!(libc::SYS_symlink, 2, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
            val.creates_symlink = true;
        }

        define_paths_deletion_syscall!(libc::SYS_unlink, 1, DelType::File, iter, next);
        if let Some(val) = iter[next].as_mut() {
            val.dont_follow_symlink = true;
        }

        define_paths_deletion_syscall!(libc::SYS_rmdir, 1, DelType::Dir, iter, next);
        define_paths_fileperms_syscall!(libc::SYS_mkdir, 1, PermType::Chmod, 1, iter, next);
    }
    iter
};

pub struct SyscallInfos {
    syscall_to_index: [Option<usize>; MAX_SYSCALL_NUMBER],
}

impl SyscallInfos {
    pub const fn new() -> Self {
        let mut syscall_to_index = [const { None }; MAX_SYSCALL_NUMBER];
        let mut index = 0;
        while index < RAW_SYSCALL_INFOS.len() {
            if let Some(val) = RAW_SYSCALL_INFOS[index].as_ref() {
                if val.num as usize >= MAX_SYSCALL_NUMBER {
                    panic!("Syscall number out of bound");
                }
                syscall_to_index[val.num as usize] = Some(index);
            }
            index += 1;
        }
        Self { syscall_to_index }
    }

    pub fn get(&self, syscall_num: &usize) -> Option<&SyscallInfo> {
        let syscall_num = *syscall_num;
        if syscall_num >= MAX_SYSCALL_NUMBER {
            return None;
        }
        let Some(idx) = self.syscall_to_index[syscall_num] else {
            return None;
        };
        RAW_SYSCALL_INFOS[idx].as_ref()
    }
}

pub const SYSCALL_INFOS: SyscallInfos = SyscallInfos::new();

#[repr(C)]
pub struct BpfFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

pub type SeccompFiltersArray = [BpfFilter; 2 * MAX_RAW_SYSCALL_INFOS + 2];

#[repr(C)]
pub struct SeccompFilters {
    pub filters: SeccompFiltersArray,
    pub actual_len: usize,
}

#[repr(C)]
pub struct BpfProgram {
    pub len: u16,
    pub filters_ptr: usize,
}

// We have to redefine these constants because libc doesn't set them for android
const BPF_LD: u16 = 0;
const BPF_ABS: u16 = 0x20;
const BPF_W: u16 = 0;
const BPF_K: u16 = 0;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const SECCOMP_SYSCALL_OFFSET: u32 = 0;
const SECCOMP_RET_TRACE: u32 = 0x7ff00000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

const DEFAULT_FILTER: BpfFilter = BpfFilter {
    code: BPF_RET,
    jt: 0,
    jf: 0,
    k: SECCOMP_RET_ALLOW,
};

#[allow(dead_code)]
pub const SECCOMP_FILTERS: SeccompFilters = {
    if RAW_SYSCALL_INFOS.len() > MAX_RAW_SYSCALL_INFOS {
        panic!("Too many ptrace-eligible syscalls to fit in SECCOMP BPF filter");
    }

    let mut filters = [const { DEFAULT_FILTER }; 2 * MAX_RAW_SYSCALL_INFOS + 2];

    filters[0] = BpfFilter {
        code: BPF_LD + BPF_W + BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_SYSCALL_OFFSET,
    };

    let mut idx = 0;
    let mut write_idx = 1;
    while idx < RAW_SYSCALL_INFOS.len() {
        let Some(info) = RAW_SYSCALL_INFOS[idx].as_ref() else {
            idx += 1;
            continue;
        };
        let num = info.num as u32;
        filters[write_idx] = BpfFilter {
            code: BPF_JMP + BPF_JEQ + BPF_K,
            jt: 0,
            jf: 1,
            k: num,
        };
        write_idx += 1;
        filters[write_idx] = BpfFilter {
            code: BPF_RET + BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_TRACE,
        };
        write_idx += 1;
        idx += 1;
    }
    filters[write_idx] = BpfFilter {
        code: BPF_RET + BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    };
    SeccompFilters {
        filters,
        actual_len: write_idx + 1,
    }
};

#[cfg(any(target_arch = "aarch64"))]
pub const SYSCALL_INSTRUCTION_SIZE: usize = 4;

#[cfg(not(any(target_arch = "aarch64")))]
pub const SYSCALL_INSTRUCTION_SIZE: usize = 2;

pub fn get_syscall(syscall_num: usize) -> (Option<&'static SyscallInfo>, String) {
    let syscall_info = SYSCALL_INFOS.get(&syscall_num);
    let syscall_num_str = syscall_num.to_string();
    let syscall_name = syscall_info
        .map(|x| format!("{}({})", x.name(), &syscall_num_str))
        .unwrap_or(syscall_num_str);
    (syscall_info, syscall_name)
}
