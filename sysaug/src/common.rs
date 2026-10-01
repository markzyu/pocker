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

use krsm::AsyncRuntimeError;
use pocker_executor::{PtraceFutureTypes, PtraceStatus};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::path::PathBuf;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use thiserror::Error;
use tracing::{Level, event};

#[derive(Debug, Error)]
pub enum SysAugError {
    #[error("Unexpected internal error from ptrace() executor: {0}")]
    InternalExecutor(#[from] pocker_executor::PtraceExecutorError),

    #[error("Failed to parse waitpid result: {0}")]
    ParseWaitStatus(nix::Error),

    #[error("Procfs error: {0}")]
    Procfs(#[from] pocker_procfs::ProcfsError),

    #[error("Ptrace error: {0}")]
    Ptrace(#[from] pocker_ptrace::PtraceError),

    #[error("PTRACE_DETACH error")]
    PtraceDetach(nix::Error),

    #[error("PTRACE_GETSIGINFO error")]
    PtraceGetSigInfo,

    #[error("PTRACE_GETSIGINFO error: {0}")]
    PtraceGetSigInfo2(nix::Error),

    #[error("PTRACE_PEEKDATA error: {0}")]
    PtraceRead(nix::Error),

    #[error("PTRACE_SETOPTIONS error: {0}")]
    PtraceSetOptions(nix::Error),

    #[error("PTRACE_SYSCALL error: {0}")]
    PtraceSyscall(nix::Error),

    #[error("PTRACE_CONT error: {0}")]
    PtraceContinue(nix::Error),

    #[error("Cannot get kernel version: {0}")]
    ReadKernelVersion(nix::Error),

    #[error("Cannot parse kernel version: {0}")]
    ParseKernelVersion(String),

    #[error("Not a valid absolute path: {0}")]
    AbsolutePath(std::path::PathBuf),

    #[error("Cannot convert to absolute path: {0}")]
    ConvertAbsolutePath(std::io::Error),

    #[error("Cannot convert to absolute path: prefix did not match chroot path")]
    ConvertAbsolutePathPrefix,

    #[error("Unable to find tracee's dirfd directory")]
    DirfdReg,

    #[error("Unable to detach tracee for gdb to attach: {0}")]
    GDBDetach(nix::Error),

    #[error("Unable to run gdb: {0}")]
    GDB(std::io::Error),

    #[error("Interger conversion error")]
    IntoInt,

    #[error("Cannot list metadata files in folder, because: {0}")]
    ListMetadata(std::io::Error),

    #[error("Cannot lock/unlock tracee handler")]
    LockTraceeHandler,

    #[error("Tracee process exited/crashed unexpectedly")]
    TraceeCrashed,

    #[error("Failed to write metadata: {0}")]
    WriteMetadata(String),

    #[error("Failed to create .metadata folder: {0}")]
    MetadataDir(std::io::Error),

    #[error("Failed to delete metadata: {0}")]
    DeleteMetadata(std::io::Error),

    #[error("Unexpected null value for {0}")]
    NullValue(String),

    #[error("Unimplemented system call")]
    UnimplementedAugment,

    #[error("Unable to read binary file: {0}")]
    ReadBin(std::io::Error),

    #[error("Unable to read symlink: {0}")]
    ReadSymlink(std::io::Error),

    #[error("{kind} error from '{mod_name}' mod: {message}")]
    Mod {
        kind: String,
        message: String,
        mod_name: String,
    },

    #[error("Internal error, tracee initializing but missing original regs")]
    InitMissingSavedRegs,

    #[error(
        "Internal error, ptrace async executor unblocked without correct status: {0:?} vs {1:?}"
    )]
    AsyncMismatch(PtraceFutureTypes, PtraceStatus),

    #[error(
        "Internal error, ptrace async executor expected normal syscall workflow, but got: {0}; status: {1:?}"
    )]
    AsyncMisMatchSyscall(&'static str, PtraceStatus),

    #[error("Internal error, unexpected error from KRSM async runtime: {0}")]
    AsyncRuntime(AsyncRuntimeError),

    #[error("Internal error, weak reference is no longer valid")]
    WeakReference,

    #[error("Failed to initialize seccomp")]
    SeccompInit,

    #[error("Failed to read rootfs metadata json: {0}")]
    ParseRootFsMetadata(serde_json::Error),

    #[error("Failed to write rootfs metadata json: {0}")]
    WriteRootFsMetadata(std::io::Error),

    #[error("Failed to write rootfs metadata json: {0}")]
    WriteRootFsMetadata2(serde_json::Error),

    #[error("Failed to create lock for rootfs metadata")]
    LockRootFsMetadata,

    #[error("Failed to check whether rootfs metadata exists: {0}")]
    CheckRootFsMetadata(std::io::Error),

    #[error("Internal error: bad syscall config: {0}")]
    SyscallMissingField(&'static str),

    #[error("Failed to create hardlink: {0}")]
    CreateHardlinkIO(std::io::Error),

    #[error("Failed to move metadata: {0}")]
    RenameMetadata(std::io::Error),

    #[error("Failed to stat the backing file of a hardlink: {0}")]
    StatHardlinkIO(std::io::Error),
}

#[derive(Clone, Debug, Default)]
pub struct SysAugArgs {
    pub chroot: Option<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub perms_mode: PermsMode,
    pub fail_fast: bool,
    pub fix_sigsys: bool,
    pub fix_mmap: bool,
    pub no_seccomp: bool,
    pub gdb: bool,
    pub gdb_at: Option<u64>,

    /// Use the host ld.so instead of the one from the chroot environment
    pub use_native_loader: bool,
}

// ------------------- AUGMENTS -------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Augments {
    Clone,
    Exec,
    Paths,
    Perms,
    Seccomp,
    Waitpid,
    None,
    Unimplemented,
}

impl Default for Augments {
    fn default() -> Augments {
        Augments::None
    }
}

#[derive(Debug, PartialEq)]
pub enum PathAction {
    // Encountered a symlink loop
    ELOOP,

    // No action
    None,

    // Hide this path from getdents
    HidePath,

    // Override the name of this path
    Override(PathBuf),
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootFsMetadata {
    pub chmod: Option<usize>,
    pub chown_owner: Option<usize>,
    pub chown_group: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_symlink: Option<bool>,

    /// This is set if and only if the file is a hard link
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardlink_counter: Option<usize>,
}

// ------------------- SYSCALLS -------------------

#[derive(Clone, Debug, PartialEq)]
pub enum DelType {
    File,
    Dir,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PermType {
    Chmod,
    ChmodOnCreation,
    Chown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum PermsMode {
    #[default]
    Passthrough,
    RootOnly,
    SudoOnly,
}

#[derive(Clone, Debug)]
pub struct SyscallInfo {
    /// The type of augment that will handle this syscall
    pub augment: Augments,
    /// The syscall argument that stores flags like AT_SYMLINK_NOFOLLOW
    pub flags: Option<usize>,

    // Naming conventions:
    // "positions" = Bitwise representation. Bit0: arg0 is path. Bit1 = arg1 ...
    // "position" = None, or, Some(register) (0 = arg0, 1 = arg1, 2 = arg2 ...)
    pub path_positions: usize,
    pub dirfd_position: Option<u8>,
    pub filefd_position: Option<u8>,
    pub dirfd_precedes_path: bool,
    pub getdents_bits: Option<u8>,
    pub stat_buf_position: Option<u8>,
    pub stat_legacy_buf_position: Option<u8>,
    pub stat64_buf_position: Option<u8>,
    pub statx_buf_position: Option<u8>,
    pub sets_file_perms: Option<PermType>,
    pub file_perms_position: Option<u8>,
    pub deletion_type: Option<DelType>,
    pub dont_follow_symlink: bool,
    pub flag_dont_follow_symlink: Option<usize>,

    /// The register storing the location of the link target and link name
    pub creates_symlink: Option<(u8, u8)>,

    /// A note on hardlinks:
    ///
    /// Hardlinks are stored in the metadata folder, and the links themselves
    /// are just symlinks to that content.
    ///
    /// Most system calls should never "follow hardlink". (the syscall args shouldn't)
    ///
    /// > If someone `rename(link_a, b)`,
    /// > It shouldn't send a system call to rename the `.metadata/links/id` to `b`.
    /// > But it should rename the `link_a` (symlink).
    ///
    /// One exception is `stat`. We should be showing the stat of the content file
    ///
    /// Another is metadata. All links share permission. So they share metadata at
    /// `.metadata/links/id.json`. However, we need to handle `unlink()` differently,
    /// which must check `RootfsMetadata::hardlink_counter` before removing metadata.
    pub creates_hardlink: Option<(u8, u8)>,

    /// This indicates a aug_paths syscall. register ids are stored as (from, to)
    pub renames_metadata: Option<(u8, u8)>,

    /// true -> setuid/setgid, false -> getuid/getgid
    pub is_setter: bool,
    /// a bitmask of Real/Effective/SavedSet/FileSystem/IsUid flags (from 0 to 31). One call can set multiple flags at once.
    pub res_bits: u8,
    /// the direct index of the perms_ids slot (from 0 to 8: rgid, egid, ssgid, fsgid, ruid, euid, ssuid, fsuid)
    pub resf_bit: Option<u8>,

    /// The register location that store the seccomp operation flag
    pub seccomp_position: Option<usize>,

    pub num: libc::c_long,
    pub name: &'static str,
}

pub const fn default_syscall_info() -> SyscallInfo {
    SyscallInfo {
        augment: Augments::None,
        flags: None,
        path_positions: 0,
        dirfd_position: None,
        filefd_position: None,
        dirfd_precedes_path: false,
        getdents_bits: None,
        stat_buf_position: None,
        stat_legacy_buf_position: None,
        stat64_buf_position: None,
        statx_buf_position: None,
        sets_file_perms: None,
        file_perms_position: None,
        deletion_type: None,
        dont_follow_symlink: false,
        flag_dont_follow_symlink: None,
        creates_symlink: None,
        creates_hardlink: None,
        renames_metadata: None,
        is_setter: false,
        res_bits: 0,
        resf_bit: None,
        seccomp_position: None,
        num: 0,
        name: "",
    }
}

impl Default for SyscallInfo {
    fn default() -> SyscallInfo {
        default_syscall_info()
    }
}

impl SyscallInfo {
    pub fn name(&self) -> &str {
        &self.name[10..]
    }
}

// We promise not to modify this system call
pub const NO_MOD_SYSCALL: usize = libc::SYS_getpid as usize;

// ------------------- Missing libc constants -------------------

#[allow(dead_code)]
pub const PR_SET_SECCOMP: usize = 22;

#[allow(dead_code)]
pub const PR_SET_NO_NEW_PRIVS: usize = 38;

#[allow(dead_code)]
pub const SECCOMP_SET_MODE_FILTER: usize = 1;

#[allow(dead_code)]
pub const SECCOMP_FILTER_FLAG_TSYNC: usize = 1;

#[allow(dead_code)]
pub const PTRACE_SYSCALL_INFO_NONE: u8 = 0;

#[allow(dead_code)]
pub const PTRACE_SYSCALL_INFO_ENTRY: u8 = 1;

#[allow(dead_code)]
pub const PTRACE_SYSCALL_INFO_EXIT: u8 = 2;

#[allow(dead_code)]
pub const PTRACE_SYSCALL_INFO_SECCOMP: u8 = 3;

#[allow(dead_code)]
pub const SI_CODE_SYS_SECCOMP: libc::c_int = 1;

#[cfg(not(target_arch = "arm"))]
pub const SYS_MMAP: usize = libc::SYS_mmap as usize;
#[cfg(target_arch = "arm")]
pub const SYS_MMAP: usize = libc::SYS_mmap2 as usize;

#[cfg(not(target_arch = "arm"))]
pub const SYS_MMAP_PGOFFSET_BLOCK: usize = 1;
#[cfg(target_arch = "arm")]
pub const SYS_MMAP_PGOFFSET_BLOCK: usize = 4096;

pub const PTRACE_EVENT_SECCOMP: libc::c_int =
    nix::sys::ptrace::Event::PTRACE_EVENT_SECCOMP as libc::c_int;

// ------------------- MISC -------------------

pub fn display_err<E: Display>(e: E) -> E {
    event!(Level::ERROR, "Error: {}", e);
    e
}

pub fn rwlock_read<T>(lock: &RwLock<T>) -> Result<RwLockReadGuard<'_, T>, SysAugError> {
    lock.read().or(Err(SysAugError::LockTraceeHandler))
}

pub fn rwlock_write<T>(lock: &RwLock<T>) -> Result<RwLockWriteGuard<'_, T>, SysAugError> {
    lock.write().or(Err(SysAugError::LockTraceeHandler))
}

pub fn rwlock_replace<T>(lock: &RwLock<T>, val: T) -> Result<(), SysAugError> {
    let mut guard = rwlock_write(lock)?;
    *guard = val;
    Ok(())
}

pub fn rwoption_replace<T>(lock: &RwLock<Option<T>>, val: T) -> Result<Option<T>, SysAugError> {
    let mut guard = rwlock_write(lock)?;
    Ok(guard.replace(val))
}

pub fn rwoption_setdefault<T>(lock: &RwLock<Option<T>>, val: T) -> Result<(), SysAugError> {
    let mut guard = rwlock_write(lock)?;
    if guard.is_none() {
        guard.replace(val);
    }
    Ok(())
}

pub fn rwoption_take<T>(lock: &RwLock<Option<T>>) -> Result<Option<T>, SysAugError> {
    let mut guard = rwlock_write(lock)?;
    Ok(guard.take())
}
