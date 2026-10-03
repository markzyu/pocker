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

use crate::common::{PathAction, SysAugError, SyscallInfo};
use crate::handler_async::{AsyncTraceeHandler, get_mem_helper};
use crate::{PermType, display_err};
use pocker_ptrace::{
    GenericPurposeRegs, MemHelpers, getregs, read_bytes_to_fixed_sized_objs, read_bytes_to_structs,
    setregs, write_fixed_sized_objs_to_tracee, write_structs_to_tracee,
};
use std::cell::RefCell;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use tracing::{Level, event};

/// Per Linux inode.7 documentation, stx_mode needs a mask, if we only want to manipulate chmod
const FILE_PERMS_MASK: usize = 0o7777;

const EACCES: usize = -libc::EACCES as usize;
const EEXIST: usize = -libc::EEXIST as usize;

// The StrongFuture will output (regs after system call, retval of system call)
type StrongWeakOutput = Result<(GenericPurposeRegs, isize), SysAugError>;
type StrongWeakBuilder<F> = krsm::StrongWeakBuilder<StrongWeakOutput, F>;

// How many system call arguments are considered
const ARGS_LEN: usize = 5;

// This is a helper struct that holds registers and parsed paths during syscall-entry
struct AugmentState {
    entry_regs: RefCell<GenericPurposeRegs>,
    orig_args: [usize; ARGS_LEN],
    save_paths: RefCell<[Option<PathBuf>; ARGS_LEN]>,
    need_write_regs: RefCell<bool>,
    // This is a bitmask for bits in 0..ARGS_LEN
    need_write_paths: RefCell<usize>,
    // This stores the system call return value if skipped
    need_skip_syscall: RefCell<Option<usize>>,
}

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub async fn augment_sys_paths(
        &self,
        orig_regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let pid = self.pid;
        let ptrace_client = &self.ptrace_client;
        let state = self._aug_paths_do_parse_state(orig_regs, syscall)?;

        // If we already need to skip system call, then, skip it. (it's an ELOOP)
        let maybe_skip_syscall_retval = { *state.need_skip_syscall.borrow() };
        if let Some(retval) = maybe_skip_syscall_retval {
            self.do_skip_syscall(retval).await?;
            return Ok(());
        }

        // Run synchronous augments first
        self.augment_deletion(syscall, &state)?;
        self.augment_hardlink_following(syscall, &state)?;

        let syscall_future = async {
            // Write new paths into register
            let need_skip_syscall = { state.need_skip_syscall.borrow().clone() };
            let need_write_paths = { *state.need_write_paths.borrow() };
            for i in 0..ARGS_LEN {
                let check_bit: usize = 1 << i;
                if (need_write_paths & check_bit) == 0 {
                    continue;
                }
                let save_paths = state.save_paths.borrow();
                if let Some(path) = save_paths[i].as_ref() {
                    let tracee_addr = self.tracee_stack_append_path(path.clone())?;
                    state.write_arg(i, tracee_addr);
                }
            }

            // Write new register to tracee
            let need_write_regs = { *state.need_write_regs.borrow() };
            if need_write_regs && need_skip_syscall.is_none() {
                let regs = state.entry_regs.borrow().clone();
                ptrace_client.execute(move || setregs(pid, regs))??;
            }

            // Perform system call
            if let Some(retval) = need_skip_syscall {
                self.do_skip_syscall(retval).await?;
                let regs = ptrace_client.execute(move || getregs(pid))??;
                StrongWeakOutput::Ok((regs, retval as isize))
            } else {
                let regs = self.do_resume_syscall().await?;
                let retval = regs.syscall_retval();
                StrongWeakOutput::Ok((regs, retval as isize))
            }
        };
        let strong_builder = krsm::upgrade(syscall_future);
        let strong_pinned = pin!(strong_builder);

        let weak_group1 = futures_lite::future::try_zip(
            futures_lite::future::try_zip(
                self.augment_chmod(strong_pinned.as_ref(), syscall, &state),
                self.augment_chmod_on_creation(strong_pinned.as_ref(), syscall, &state),
            ),
            futures_lite::future::try_zip(
                self.augment_chown(strong_pinned.as_ref(), syscall, &state),
                self.augment_rename(strong_pinned.as_ref(), syscall, &state),
            ),
        );
        let weak_group2 = futures_lite::future::try_zip(
            futures_lite::future::try_zip(
                self.augment_symlink_creation(strong_pinned.as_ref(), syscall, &state),
                self.augment_hardlink_creation(strong_pinned.as_ref(), syscall, &state),
            ),
            futures_lite::future::try_zip(
                self.augment_getdents(strong_pinned.as_ref(), syscall, &state),
                self.augment_stat(strong_pinned.as_ref(), syscall, &state),
            ),
        );
        let weak_future = futures_lite::future::try_zip(weak_group1, weak_group2);
        let result = strong_pinned.as_ref().build(weak_future).await;
        if let Err(Some(e)) = result {
            return Err(e);
        }
        Ok(())
    }

    // Parse register upon syscall-entry, into aug_path::AugmentState
    fn _aug_paths_do_parse_state(
        &self,
        entry_regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<AugmentState, SysAugError> {
        let pid = self.pid;
        let ptrace_client = &self.ptrace_client;
        let MemHelpers {
            read_bytes_until_zero,
            ..
        } = get_mem_helper();

        // Translate paths from host namespace to tracee namespace
        let orig_args = [
            entry_regs.arg0,
            entry_regs.arg1,
            entry_regs.arg2,
            entry_regs.arg3,
            entry_regs.arg4,
        ];
        let mut save_paths: [Option<PathBuf>; ARGS_LEN] = Default::default();
        let mut need_write_paths: usize = 0;
        for i in 0..ARGS_LEN {
            let check_bit: usize = 1 << i;
            if (check_bit & syscall.path_positions) == 0 {
                continue;
            }
            let arg_i = orig_args[i];
            if arg_i == 0 {
                continue;
            }

            let dirfd_path = self
                .get_dirfd_path(&entry_regs, syscall, i)?
                .unwrap_or("".into());

            // Read orig_path from registers
            // TODO: This can cause buffer overflow if tracee is malicious.
            let path_bytes =
                ptrace_client.execute(move || (read_bytes_until_zero)(pid, arg_i))??;
            let orig_path_buf = Self::path_from_bytes(path_bytes)?;

            // Calculate path_action, and maybe update tracee
            let path_action = self.calc_real_path(&orig_path_buf, syscall, &orig_args)?;

            let final_path = match path_action {
                PathAction::Override(new_path_val) => {
                    need_write_paths |= check_bit;
                    new_path_val
                }
                PathAction::ELOOP => {
                    let retval = -libc::ELOOP as usize;
                    return Ok(AugmentState {
                        entry_regs: RefCell::new(entry_regs),
                        orig_args,
                        save_paths: RefCell::new(save_paths),
                        need_skip_syscall: RefCell::new(Some(retval)),
                        need_write_paths: RefCell::new(need_write_paths),
                        need_write_regs: RefCell::new(false),
                    });
                }
                _ => orig_path_buf,
            };

            // Consider dirfd
            let final_path = if final_path.as_os_str().is_empty() {
                // In case of AT_EMPTY_PATH/empty relative path, just pass dirfd_path only
                dirfd_path.to_path_buf()
            } else {
                dirfd_path.join(&final_path)
            };
            save_paths[i] = Some(final_path);
        }

        // Handle filefd_position (This overwrites all other save_paths)
        if let Some(position) = syscall.filefd_position {
            let position = position as usize;
            let fd = orig_args[position] as isize;
            let fd_path = pocker_procfs::getfd_path(pid, fd)?.unwrap_or("".into());
            event!(Level::INFO, "filefd path {:?}", &fd_path);

            // There is no need to calc_real_path, and no need to update register,
            // because pocker cannot override real fds
            save_paths[position].replace(fd_path);
        }

        Ok(AugmentState {
            entry_regs: RefCell::new(entry_regs),
            orig_args,
            save_paths: RefCell::new(save_paths),
            need_skip_syscall: RefCell::new(None),
            need_write_paths: RefCell::new(need_write_paths),
            need_write_regs: RefCell::new(false),
        })
    }

    async fn augment_getdents<F: Future<Output = StrongWeakOutput>>(
        &self,
        future_builder: Pin<&StrongWeakBuilder<F>>,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), Option<SysAugError>> {
        // Before system call, make the buffer seem smaller
        if syscall.getdents_bits.is_some() {
            state.write_arg(2, state.orig_args[2] / 2);
        }

        // Resume system call, and drop the WeakFutureGuard
        let (regs, retval) = {
            let guard = krsm::downgrade(future_builder).await;
            let (regs, retval) = guard.as_ref().or(Err(None))?;
            (regs.clone(), *retval)
        };

        if retval <= 0 {
            return Ok(());
        }

        // After system call, replace results
        match syscall.getdents_bits {
            Some(32) => {
                self.replace_getdents_result::<Dirent>(syscall, regs)
                    .await?
            }
            Some(64) => {
                self.replace_getdents_result::<Dirent64>(syscall, regs)
                    .await?
            }
            _ => (),
        };
        Ok(())
    }

    /// Rename metadata as well.
    async fn augment_rename<F: Future<Output = StrongWeakOutput>>(
        &self,
        future_builder: Pin<&StrongWeakBuilder<F>>,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), Option<SysAugError>> {
        // First, check for hardlinks
        // Handle rename when target is a hardlink
        let Some((i, j)) = syscall.renames_metadata else {
            return Ok(());
        };
        let metadir = self.get_metadata_dir();
        let i = i as usize;
        let j = j as usize;

        if let Some(metadir) = metadir.as_ref() {
            state.saved_path_pair(i, j, |path1, path2| {
                let Ok(path1) = path1.canonicalize() else {
                    return Ok(());
                };
                let Ok(path2) = path2.canonicalize() else {
                    return Ok(());
                };
                if !path1.exists() || !path2.exists() {
                    return Ok(());
                }
                let is_hardlink1 = path1.starts_with(metadir);
                let is_hardlink2 = path2.starts_with(metadir);
                if is_hardlink1 && is_hardlink2 && path1 == path2 {
                    state.set_skip_syscall(0);
                } else if is_hardlink2 {
                    // Decrease reference counter by 1
                    self.delete_metadata_for_file(path2.as_path())?;
                }
                Ok(())
            })?;
        }

        // Resume system call, and drop the WeakFutureGuard
        let retval = {
            let guard = krsm::downgrade(future_builder).await;
            guard.as_ref().or(Err(None))?.1
        };

        if retval < 0 {
            return Ok(());
        }

        // After system call: Names are different from before-syscall because files changed
        if let Some(metadir) = metadir.as_ref() {
            let mut is_hardlink2: bool = false;
            state.saved_path_idx(j, |path2| {
                let Ok(path2) = path2.canonicalize() else {
                    return Ok(());
                };
                is_hardlink2 = path2.starts_with(metadir);
                Ok(())
            })?;
            if is_hardlink2 {
                return Ok(());
            }
        }

        state.saved_path_pair(i, j, |path1, path2| {
            let path1 = self.get_metadata_path(path1.as_path())?;
            let path2 = self.get_metadata_path(path2.as_path())?;
            if let (Some(path1), Some(path2)) = (path1, path2) {
                std::fs::rename(path1, path2).map_err(SysAugError::RenameMetadata)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    async fn augment_symlink_creation<F: Future<Output = StrongWeakOutput>>(
        &self,
        future_builder: Pin<&StrongWeakBuilder<F>>,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), Option<SysAugError>> {
        // Wait for system call
        let _ = krsm::downgrade(future_builder).await;

        // After system call
        if let Some((_, i)) = syscall.creates_symlink {
            let i = i as usize;
            state.saved_path_idx(i, |path| {
                self.save_metadata_for_file(path, |x| x.is_symlink = Some(true))?;
                Ok(())
            })?;
        }
        Ok(())
    }

    async fn augment_hardlink_creation<F: Future<Output = StrongWeakOutput>>(
        &self,
        future_builder: Pin<&StrongWeakBuilder<F>>,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), Option<SysAugError>> {
        let Some((i, j)) = syscall.creates_hardlink else {
            return Ok(());
        };
        let Some(metadir) = self.get_metadata_dir() else {
            return Ok(());
        };

        // Create hardlinks by (1) moving the original file (2) creating two symlinks (3) skip system call
        let i = i as usize;
        let j = j as usize;
        state.saved_path_pair(i, j, |path, result_path| {
            let path = path.canonicalize().map_err(SysAugError::CreateHardlinkIO)?;
            if !path.exists() {
                return Ok(());
            }

            let target_path = if path.starts_with(&metadir) {
                path.clone()
            } else {
                let links_dir = metadir.join("links");
                let uuid = uuid::Uuid::new_v4().to_string();
                let new_meta = links_dir.join(format!("{}.json", &uuid));
                let target_path = links_dir.join(uuid);

                // First, move the metadata
                std::fs::create_dir_all(&links_dir).map_err(SysAugError::CreateHardlinkIO)?;
                if let Some(old_meta) = self.get_metadata_path(&path)? {
                    let _ = std::fs::rename(&old_meta, &new_meta)
                        .map_err(SysAugError::CreateHardlinkIO)
                        .map_err(display_err);
                };

                // Then, move the link content
                std::fs::rename(&path, &target_path).map_err(SysAugError::CreateHardlinkIO)?;

                // Then, setup symlinks
                symlink(&target_path, &path).map_err(SysAugError::CreateHardlinkIO)?;
                self.increment_hardlink_counter(&path)?;
                target_path
            };

            let rootfs_path = self.consts.args.rootfs.as_ref().unwrap();
            if !result_path.starts_with(rootfs_path) {
                state.set_skip_syscall(EACCES);
            } else if result_path.exists() {
                state.set_skip_syscall(EEXIST);
            } else {
                symlink(&target_path, result_path).map_err(SysAugError::CreateHardlinkIO)?;
                state.set_skip_syscall(0);
            }
            Ok(())
        })?;

        // Resume system call, and drop the WeakFutureGuard
        let retval = {
            let guard = krsm::downgrade(future_builder).await;
            guard.as_ref().or(Err(None))?.1
        };

        if retval < 0 {
            return Ok(());
        }

        // After system call.
        state.saved_path_idx(j, |path| self.increment_hardlink_counter(path))?;
        Ok(())
    }

    // An augment function is synchronous if it only cares about the syscall-entry
    fn augment_hardlink_following(
        &self,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), SysAugError> {
        if !syscall.should_follow_hardlink {
            return Ok(());
        }

        state.first_saved_path_mut(|pathbuf, i| {
            let path = pathbuf.as_path();
            if let Some(meta) = self.read_metadata_for_file(path)?
                && meta.hardlink_counter.is_some()
            {
                // Resolve the actual path of the hardlink
                *pathbuf = path.canonicalize().map_err(SysAugError::StatHardlinkIO)?;

                // Set dirfd to AT_FDCWD to avoid ELOOP on some Linux
                if syscall.dirfd_precedes_path {
                    state.write_arg(i - 1, libc::AT_FDCWD as usize);
                }

                if let Some(j) = syscall.dirfd_position {
                    state.write_arg(j as usize, libc::AT_FDCWD as usize);
                }
                return Ok(true);
            }
            Ok(false)
        })?;
        Ok(())
    }

    // An augment function is synchronous if it only cares about the syscall-entry
    fn augment_deletion(
        &self,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), SysAugError> {
        if !syscall.deletion_type.is_some() {
            return Ok(());
        }

        state.for_saved_path(|path| {
            self.delete_metadata_for_file(path)?;
            Ok(())
        })?;
        Ok(())
    }

    fn increment_hardlink_counter(&self, path: &PathBuf) -> Result<(), SysAugError> {
        self.save_metadata_for_file(path, |x| {
            if let Some(count) = x.hardlink_counter {
                x.hardlink_counter = Some(count + 1);
            } else {
                x.hardlink_counter = Some(1);
            }
        })?;
        Ok(())
    }

    async fn augment_chown<F: Future<Output = StrongWeakOutput>>(
        &self,
        future_builder: Pin<&StrongWeakBuilder<F>>,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), Option<SysAugError>> {
        if &syscall.sets_file_perms != &Some(PermType::Chown) {
            return Ok(());
        }

        // Before system call
        let position = &syscall
            .file_perms_position
            .ok_or(SysAugError::SyscallMissingField(
                "Chown syscall doesn't have sets_file_perms",
            ))?;
        state.write_arg(*position as usize, self.consts.config.rootfs.host_uid);
        state.write_arg(*position as usize + 1, self.consts.config.rootfs.host_gid);

        // Resume system call, and drop the WeakFutureGuard
        let _ = krsm::downgrade(future_builder).await;

        // After system call
        let new_owner = state.orig_args[*position as usize];
        let new_group = state.orig_args[(*position + 1) as usize];
        state.for_saved_path(|path| {
            event!(
                Level::INFO,
                "Handling chown: {:?}, {}, {}",
                &path,
                new_owner,
                new_group
            );
            self.save_metadata_for_file(path, |x| {
                x.chown_owner = Some(new_owner);
                x.chown_group = Some(new_group);
            })?;
            Ok(())
        })?;
        Ok(())
    }

    async fn augment_chmod<F: Future<Output = StrongWeakOutput>>(
        &self,
        future_builder: Pin<&StrongWeakBuilder<F>>,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), Option<SysAugError>> {
        if &syscall.sets_file_perms != &Some(PermType::Chmod) {
            return Ok(());
        }

        // Before system call
        let position = &syscall
            .file_perms_position
            .ok_or(SysAugError::SyscallMissingField(
                "Chmod syscall doesn't have sets_file_perms",
            ))?;
        state.write_arg(
            *position as usize,
            self.consts.config.rootfs.host_file_perms,
        );

        // Resume system call, and drop the WeakFutureGuard
        let _ = krsm::downgrade(future_builder).await;

        // After system call
        let new_mod = state.orig_args[*position as usize];
        state.for_saved_path(|path| {
            event!(Level::INFO, "Handling chmod: {:?}, {:b}", &path, new_mod);
            self.save_metadata_for_file(path, |x| x.chmod = Some(new_mod & FILE_PERMS_MASK))?;
            Ok(())
        })?;
        Ok(())
    }

    async fn augment_chmod_on_creation<F: Future<Output = StrongWeakOutput>>(
        &self,
        future_builder: Pin<&StrongWeakBuilder<F>>,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), Option<SysAugError>> {
        if &syscall.sets_file_perms != &Some(PermType::ChmodOnCreation) {
            return Ok(());
        }

        // Before system call
        let flags_position = &syscall.flags.ok_or(SysAugError::SyscallMissingField(
            "ChmodOnCreation syscall doesn't have flags",
        ))?;
        let perms_position =
            &syscall
                .file_perms_position
                .ok_or(SysAugError::SyscallMissingField(
                    "ChmodOnCreation syscall doesn't have sets_file_perms",
                ))?;
        state.write_arg(
            *perms_position as usize,
            self.consts.config.rootfs.host_file_perms,
        );

        // Resume system call, and drop the WeakFutureGuard
        let _ = krsm::downgrade(future_builder).await;

        // After system call
        let flags = state.orig_args[*flags_position];
        if flags & (libc::O_CREAT as usize) != 0 {
            let new_mod = state.orig_args[*perms_position as usize];
            state.for_saved_path(|path| {
                event!(Level::INFO, "Handling chmod: {:?}, {:b}", &path, new_mod);
                self.save_metadata_for_file(path, |x| x.chmod = Some(new_mod & FILE_PERMS_MASK))?;
                Ok(())
            })?;
        }
        Ok(())
    }

    async fn augment_stat<F: Future<Output = StrongWeakOutput>>(
        &self,
        future_builder: Pin<&StrongWeakBuilder<F>>,
        syscall: &SyscallInfo,
        state: &AugmentState,
    ) -> Result<(), Option<SysAugError>> {
        let maybe_position = syscall
            .stat_buf_position
            .or(syscall.stat_legacy_buf_position)
            .or(syscall.stat64_buf_position)
            .or(syscall.statx_buf_position);
        let Some(position) = maybe_position else {
            return Ok(());
        };

        // Resume system call, and drop the WeakFutureGuard
        let retval = {
            let guard = krsm::downgrade(future_builder).await;
            guard.as_ref().or(Err(None))?.1
        };

        if retval < 0 {
            return Ok(());
        }

        // After system call. Check `stat*_position` flags in syscall info.
        state.first_saved_path_mut(|path, _| {
            let path = path.as_path();
            let addr = state.orig_args[position as usize];
            if syscall.stat_buf_position.is_some() {
                self.replace_statbuf_result::<libc::stat>(addr, path)?;
            } else if syscall.stat_legacy_buf_position.is_some() {
                #[cfg(target_pointer_width = "32")]
                self.replace_statbuf_result::<StatLegacy>(addr, path)?;
                #[cfg(target_pointer_width = "64")]
                self.replace_statbuf_result::<libc::stat>(addr, path)?;
            } else if syscall.stat64_buf_position.is_some() {
                self.replace_statbuf_result::<libc::stat64>(addr, path)?;
            } else if syscall.statx_buf_position.is_some() {
                self.replace_statbuf_result::<libc::statx>(addr, path)?;
            }
            Ok(false)
        })?;
        Ok(())
    }

    fn get_dirfd_path(
        &self,
        regs: &GenericPurposeRegs,
        syscall: &SyscallInfo,
        i: usize,
    ) -> Result<Option<PathBuf>, SysAugError> {
        let maybe = if let Some(dirfd_reg) = syscall.dirfd_position {
            Some(dirfd_reg as isize)
        } else if syscall.dirfd_precedes_path {
            Some((i as isize) - 1)
        } else {
            None
        };
        if let Some(dirfd_reg) = maybe {
            if dirfd_reg >= 3 {
                return Err(SysAugError::DirfdReg);
            }
            let possible_args = [&regs.arg0, &regs.arg1, &regs.arg2];
            let dirfd = *possible_args[dirfd_reg as usize] as libc::c_int;
            if dirfd != libc::AT_FDCWD {
                return Ok(pocker_procfs::getfd_path(self.pid, dirfd as isize)?);
            }
        }
        // Otherwise, use cwd of tracee
        Ok(Some(pocker_procfs::getcwd(self.pid)?))
    }

    async fn replace_getdents_result<T>(
        &self,
        syscall: &SyscallInfo,
        mut regs: GenericPurposeRegs,
    ) -> Result<(), SysAugError>
    where
        T: IDirent + Clone + Send + 'static,
    {
        let mem_helpers = get_mem_helper();
        let addr = regs.arg1;
        let buf_size = regs.arg2 * 2;
        let list_size = regs.syscall_retval();
        let pid = self.pid;
        let ptrace_client = &self.ptrace_client;
        let mut dirents: Vec<T> = ptrace_client
            .execute(move || read_bytes_to_structs(pid, addr, list_size, mem_helpers))??;
        event!(Level::DEBUG, "Intercepting {} dir entries", dirents.len());

        let mut is_delete: Vec<bool> = Vec::new();
        for entry in dirents.iter_mut() {
            event!(Level::TRACE, "Intercepting {:?}", entry);
            entry.normalize_type();
            let orig_path_buf = Self::path_from_bytes(entry.get_name().to_vec())?;
            let orig_path: &Path = orig_path_buf.as_path();
            let action = self.get_mod_path(syscall, orig_path, PathAction::None, true)?;
            let delete = match &action {
                PathAction::Override(override_path) => {
                    let bytes = override_path.as_os_str().as_bytes();
                    entry.get_name().fill(0);
                    for (i, byte) in bytes.iter().take_while(|x| **x != 0).enumerate() {
                        entry.get_name()[i] = *byte;
                    }
                    false
                }
                PathAction::HidePath => true,
                _ => false,
            };
            is_delete.push(delete);
        }

        let mut i = 0;
        dirents.retain(|_e| {
            let ans = is_delete[i];
            i += 1;
            !ans
        });

        let num_dirents = dirents.len();
        let num_bytes = ptrace_client
            .execute(move || write_structs_to_tracee(pid, addr, buf_size, dirents, 2))??;
        event!(
            Level::DEBUG,
            "Returning {} dir entries, {} bytes",
            num_dirents,
            num_bytes
        );

        // Restore buffer size value so program doesn't reuse wrong values crash
        regs.arg2 *= 2;
        regs.set_syscall_retval(num_bytes);
        ptrace_client.execute(move || setregs(pid, regs))??;
        Ok(())
    }

    fn replace_statbuf_result<T>(&self, addr: usize, path: &Path) -> Result<(), SysAugError>
    where
        T: IStat + Clone + Send + 'static,
    {
        let Some(meta) = self.read_metadata_for_file(path)? else {
            return Ok(());
        };
        let mem_helpers = get_mem_helper();
        let pid = self.pid;
        let ptrace_client = &self.ptrace_client;
        let mut stats: Vec<T> = ptrace_client
            .execute(move || read_bytes_to_fixed_sized_objs(pid, addr, 1, mem_helpers))??;
        event!(
            Level::INFO,
            "Intercepting {} stat entries for {:?}.",
            stats.len(),
            path
        );

        stats.iter_mut().for_each(move |x| {
            if let Some(count) = &meta.hardlink_counter {
                x.set_hardlink_counter(*count);
            }
            if let Some(chmod) = &meta.chmod {
                let old_mode = x.get_mode();
                let new_mode = (old_mode & !FILE_PERMS_MASK) | (*chmod & FILE_PERMS_MASK);
                event!(
                    Level::INFO,
                    "Faking new file modes: {:?}: {:x} -> {:x}",
                    path,
                    old_mode,
                    new_mode
                );
                x.set_mode(new_mode);
            }
            if let Some(chown_owner) = &meta.chown_owner {
                x.set_uid(*chown_owner);
            }
            if let Some(chown_group) = &meta.chown_group {
                x.set_gid(*chown_group);
            }
        });

        let max_size = stats.len() * std::mem::size_of::<T>();
        ptrace_client
            .execute(move || write_fixed_sized_objs_to_tracee(pid, addr, max_size, stats))??;
        Ok(())
    }
}

impl AugmentState {
    fn write_arg(&self, idx: usize, val: usize) {
        let mut guard = self.entry_regs.borrow_mut();
        let mut guard2 = self.need_write_regs.borrow_mut();
        *guard2 = true;
        match idx {
            0 => guard.arg0 = val,
            1 => guard.arg1 = val,
            2 => guard.arg2 = val,
            3 => guard.arg3 = val,
            4 => guard.arg4 = val,
            _ => (),
        }
    }

    fn set_skip_syscall(&self, retval: usize) {
        let mut guard = self.need_skip_syscall.borrow_mut();
        guard.replace(retval);
    }

    fn for_saved_path(
        &self,
        iter_fn: impl Fn(&PathBuf) -> Result<(), SysAugError>,
    ) -> Result<(), SysAugError> {
        let guard = self.save_paths.borrow();
        for path in guard.iter().flatten() {
            iter_fn(path)?;
        }
        Ok(())
    }

    /// `iter_fn(pathbuf, path index in register)` must return true if it made a change to the paths
    fn first_saved_path_mut(
        &self,
        iter_fn: impl Fn(&mut PathBuf, usize) -> Result<bool, SysAugError>,
    ) -> Result<bool, SysAugError> {
        let mut guard = self.save_paths.borrow_mut();
        let i = guard.iter().position(|x| x.is_some());
        if let Some(i) = i {
            let pathbuf = (&mut guard[i]).as_mut().unwrap();
            let is_changed = iter_fn(pathbuf, i)?;
            if is_changed {
                let mut guard2 = self.need_write_paths.borrow_mut();
                *guard2 |= 1 << i;
            }
            return Ok(is_changed);
        }
        Ok(false)
    }

    /// `iter_fn(pathbuf at i)` if only called if i exists
    fn saved_path_idx(
        &self,
        i: usize,
        mut iter_fn: impl FnMut(&PathBuf) -> Result<(), SysAugError>,
    ) -> Result<(), SysAugError> {
        let guard = self.save_paths.borrow();
        let arr = &*guard;
        if let Some(pathbuf1) = arr[i].as_ref() {
            iter_fn(pathbuf1)?;
        }
        Ok(())
    }

    /// `iter_fn(pathbuf at i, pathbuf at j)` is only called if both i and j exist
    fn saved_path_pair(
        &self,
        i: usize,
        j: usize,
        iter_fn: impl Fn(&PathBuf, &PathBuf) -> Result<(), SysAugError>,
    ) -> Result<(), SysAugError> {
        let guard = self.save_paths.borrow();
        let arr = &*guard;
        let pathbuf1 = arr[i].as_ref();
        let pathbuf2 = arr[j].as_ref();
        if let Some(p1) = pathbuf1
            && let Some(p2) = pathbuf2
        {
            iter_fn(p1, p2)?;
        }
        Ok(())
    }
}

trait IDirent: pocker_ptrace::CStruct + std::fmt::Debug {
    fn get_name(&mut self) -> &mut [u8];
    fn normalize_type(&mut self);
}

#[derive(Debug, Clone)]
#[repr(C)]
struct Dirent64 {
    pub inode: libc::ino64_t,
    pub offset: libc::off64_t,
    pub reclen: libc::c_ushort,
    pub type_: libc::c_uchar,
    pub name: [u8; 512],
}

#[derive(Debug, Clone)]
#[repr(C)]
struct Dirent64Header {
    pub inode: libc::ino64_t,
    pub offset: libc::off64_t,
    pub reclen: libc::c_ushort,
}

#[derive(Debug, Clone)]
#[repr(C)]
struct Dirent {
    pub inode: libc::ino_t,
    pub offset: libc::off_t,
    pub reclen: libc::c_ushort,
    pub name: [u8; 512],
}

#[derive(Debug, Clone)]
#[repr(C)]
struct DirentHeader {
    pub inode: libc::ino_t,
    pub offset: libc::off_t,
    pub reclen: libc::c_ushort,
}

const DT_UNKNOWN: u8 = 0;
const DT_LNK: u8 = 10;

impl IDirent for Dirent64 {
    fn get_name(&mut self) -> &mut [u8] {
        &mut self.name
    }

    fn normalize_type(&mut self) {
        if self.type_ == DT_LNK {
            self.type_ = DT_UNKNOWN;
        }
    }
}
impl pocker_ptrace::CStruct for Dirent64 {
    type H = Dirent64Header;
}
impl pocker_ptrace::CHeader for Dirent64Header {
    fn item_size_deducer(&self) -> usize {
        self.reclen.into()
    }

    fn item_size_updater(&mut self, size: usize) {
        self.reclen = size as u16;
    }
}

impl IDirent for Dirent {
    fn get_name(&mut self) -> &mut [u8] {
        &mut self.name
    }

    fn normalize_type(&mut self) {}
}
impl pocker_ptrace::CStruct for Dirent {
    type H = DirentHeader;
}
impl pocker_ptrace::CHeader for DirentHeader {
    fn item_size_deducer(&self) -> usize {
        self.reclen.into()
    }

    fn item_size_updater(&mut self, size: usize) {
        self.reclen = size as u16;
    }
}

trait IStat: Sized + std::fmt::Debug {
    fn get_mode(&self) -> usize;
    fn set_mode(&mut self, val: usize);
    fn set_uid(&mut self, val: usize);
    fn set_gid(&mut self, val: usize);
    fn set_hardlink_counter(&mut self, val: usize);
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
/// Legacy version of stat used by very old 32bit kernels
struct StatLegacy {
    st_dev: u16,
    st_ino: u16,
    st_mode: u16,
    st_nlink: u16,
    st_uid: u16,
    st_gid: u16,
    st_rdev: u16,

    /// size, atime, mtime, ctime have unknown bit widths
    _paddings: [usize; 4],
}

impl IStat for libc::stat {
    fn get_mode(&self) -> usize {
        self.st_mode as usize
    }

    fn set_mode(&mut self, val: usize) {
        self.st_mode = val as u32;
    }

    fn set_gid(&mut self, val: usize) {
        self.st_gid = val as u32;
    }

    fn set_uid(&mut self, val: usize) {
        self.st_uid = val as u32;
    }

    fn set_hardlink_counter(&mut self, val: usize) {
        self.st_nlink = val as libc::nlink_t;
    }
}

impl IStat for libc::stat64 {
    fn get_mode(&self) -> usize {
        self.st_mode as usize
    }

    fn set_mode(&mut self, val: usize) {
        self.st_mode = val as u32;
    }

    fn set_gid(&mut self, val: usize) {
        self.st_gid = val as u32;
    }

    fn set_uid(&mut self, val: usize) {
        self.st_uid = val as u32;
    }

    fn set_hardlink_counter(&mut self, val: usize) {
        self.st_nlink = val as libc::nlink_t;
    }
}

impl IStat for libc::statx {
    fn get_mode(&self) -> usize {
        self.stx_mode as usize
    }

    fn set_mode(&mut self, val: usize) {
        self.stx_mode = val as u16;
    }

    fn set_gid(&mut self, val: usize) {
        self.stx_gid = val as u32;
    }

    fn set_uid(&mut self, val: usize) {
        self.stx_uid = val as u32;
    }

    fn set_hardlink_counter(&mut self, val: usize) {
        self.stx_nlink = val as u32;
    }
}

impl IStat for StatLegacy {
    fn get_mode(&self) -> usize {
        self.st_mode as usize
    }

    fn set_mode(&mut self, val: usize) {
        self.st_mode = val as u16;
    }

    fn set_gid(&mut self, val: usize) {
        self.st_gid = val as u16;
    }

    fn set_uid(&mut self, val: usize) {
        self.st_uid = val as u16;
    }

    fn set_hardlink_counter(&mut self, val: usize) {
        self.st_nlink = val as u16;
    }
}
