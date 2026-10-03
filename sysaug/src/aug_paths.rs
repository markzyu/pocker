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

#[allow(dead_code)]
impl AugmentState {
    fn update_arg(&self, idx: usize, update_fn: impl Fn(usize) -> usize) {
        let mut guard = self.entry_regs.borrow_mut();
        let mut guard2 = self.need_write_regs.borrow_mut();
        *guard2 = true;
        match idx {
            0 => guard.arg0 = update_fn(guard.arg0),
            1 => guard.arg1 = update_fn(guard.arg1),
            2 => guard.arg2 = update_fn(guard.arg2),
            3 => guard.arg3 = update_fn(guard.arg3),
            4 => guard.arg4 = update_fn(guard.arg4),
            _ => (),
        }
    }

    fn write_arg(&self, idx: usize, val: usize) {
        self.update_arg(idx, |_| val);
    }

    // Save new override for path at register idx, and mark as "write to register"
    fn save_path(&self, idx: usize, val: PathBuf) {
        let mut guard = self.save_paths.borrow_mut();
        let mut guard2 = self.need_write_paths.borrow_mut();
        guard[idx].replace(val);
        *guard2 |= 1 << idx;
    }

    // Save the path at register idx, and mark as "do NOT write to register"
    fn save_path_without_writing(&self, idx: usize, val: PathBuf) {
        let mut guard = self.save_paths.borrow_mut();
        guard[idx].replace(val);
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

    /// `iter_fn(pathbuf at i, pathbuf at j)`
    fn saved_path_pair(
        &self,
        i: usize,
        j: usize,
        iter_fn: impl Fn(Option<&PathBuf>, Option<&PathBuf>) -> Result<(), SysAugError>,
    ) -> Result<(), SysAugError> {
        let guard = self.save_paths.borrow();
        let arr = &*guard;
        let pathbuf1 = arr[i].as_ref();
        let pathbuf2 = arr[j].as_ref();
        iter_fn(pathbuf1, pathbuf2)
    }
}

fn clone<T: Clone>(cell: &RefCell<T>) -> T {
    let guard = cell.borrow();
    guard.clone()
}

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    async fn augment_sys_paths_new_state(
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
            let path_action = self
                .calc_real_path(&orig_path_buf, syscall, &orig_args)
                .await?;
            match path_action {
                PathAction::Override(new_path_val) => {
                    // In case of AT_EMPTY_PATH/empty relative path, just pass dirfd_path only
                    let input_path = if new_path_val.as_os_str().is_empty() {
                        dirfd_path.to_path_buf()
                    } else {
                        dirfd_path.join(&new_path_val)
                    };
                    save_paths[i] = Some(input_path);
                    need_write_paths |= check_bit;
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
                _ => {
                    // In case of AT_EMPTY_PATH/empty relative path, just pass dirfd_path only
                    let input_path = if orig_path_buf.as_os_str().is_empty() {
                        dirfd_path.to_path_buf()
                    } else {
                        dirfd_path.join(orig_path_buf)
                    };
                    save_paths[i] = Some(input_path);
                }
            }
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

    pub async fn augment_sys_paths(
        &self,
        orig_regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let pid = self.pid;
        let ptrace_client = &self.ptrace_client;
        let state = self.augment_sys_paths_new_state(orig_regs, syscall).await?;

        if let Some(retval) = clone(&state.need_skip_syscall) {
            self.do_skip_syscall(retval).await?;
        }

        // Handle filefd_position (This overwrites all other save_paths)
        if let Some(position) = syscall.filefd_position {
            let fd = state.orig_args[position as usize] as isize;
            let fd_path = pocker_procfs::getfd_path(pid, fd)?.unwrap_or("".into());
            event!(Level::INFO, "filefd path {:?}", &fd_path);

            // There is no need to calc_real_path, and no need to update register,
            // because pocker cannot override real fds
            state.save_path_without_writing(0, fd_path);
        }

        // Handle getdents (make the buffer seem smaller)
        if syscall.getdents_bits.is_some() {
            state.update_arg(2, |v| v / 2);
        }

        // Delete metadata before unlink & rmdir
        if syscall.deletion_type.is_some() {
            state.for_saved_path(|path| {
                self.delete_metadata_for_file(path)?;
                Ok(())
            })?;
        }

        // Handle reads of hardlinks
        if syscall.should_follow_hardlink {
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
        }

        // Create hardlinks by (1) moving the original file (2) creating two symlinks (3) skip system call
        if let Some((i, j)) = syscall.creates_hardlink
            && let Some(metadir) = self.get_metadata_dir()
        {
            let i = i as usize;
            let j = j as usize;
            state.saved_path_pair(i, j, |path, result_path| {
                let Some(path) = path else {
                    return Ok(());
                };
                let Some(result_path) = result_path else {
                    return Ok(());
                };
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
        }

        // Handle rename when target is a hardlink
        if let Some((i, j)) = syscall.renames_metadata
            && let Some(metadir) = self.get_metadata_dir()
        {
            let i = i as usize;
            let j = j as usize;
            state.saved_path_pair(i, j, |path1, path2| {
                let Some(path1) = path1 else {
                    return Ok(());
                };
                let Some(path2) = path2 else {
                    return Ok(());
                };
                let Ok(path1) = path1.canonicalize() else {
                    return Ok(());
                };
                let Ok(path2) = path2.canonicalize() else {
                    return Ok(());
                };
                if !path1.exists() || !path2.exists() {
                    return Ok(());
                }
                let is_hardlink1 = path1.starts_with(&metadir);
                let is_hardlink2 = path2.starts_with(&metadir);
                if is_hardlink1 && is_hardlink2 && path1 == path2 {
                    state.set_skip_syscall(0);
                } else if is_hardlink2 {
                    // Decrease reference counter by 1
                    self.delete_metadata_for_file(path2.as_path())?;
                }
                Ok(())
            })?;
        }

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
        let future_builder = krsm::upgrade(syscall_future);

        let weak_future = futures_lite::future::zip(
            futures_lite::future::zip(
                self.augment_chmod(&future_builder, syscall, &state),
                self.augment_chmod_on_creation(&future_builder, syscall, &state),
            ),
            self.augment_chown(&future_builder, syscall, &state),
        );
        let (_, ((r0, r1), r2)) =
            futures_lite::future::zip(future_builder.build(), weak_future).await;
        for result in [r0, r1, r2] {
            if let Err(Some(e)) = result {
                return Err(e);
            }
        }

        let (regs, retval) = future_builder.take_result()?;
        if retval < 0 {
            return Ok(());
        }

        {
            let orig_args = &state.orig_args;
            let save_paths = state.save_paths.borrow();
            self.on_stat_syscall_exit(syscall, orig_args, &*save_paths)
                .await?;
            self.on_link_syscall_exit(syscall, orig_args, &*save_paths)?;
            self.on_rename_syscall_exit(syscall, orig_args, &*save_paths)?;
        }

        if retval == 0 {
            return Ok(());
        }

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
    fn on_rename_syscall_exit(
        &self,
        syscall: &SyscallInfo,
        _args: &[usize],
        save_paths: &[Option<PathBuf>],
    ) -> Result<(), SysAugError> {
        // First, check for hardlinks
        // Reminder: This is different from on_syscall_enter because files changed
        if let Some((_, j)) = syscall.renames_metadata
            && let Some(metadir) = self.get_metadata_dir()
        {
            let j = j as usize;
            if let Some(path2) = save_paths[j].as_ref()
                && let Ok(path2) = path2.canonicalize()
            {
                let is_hardlink2 = path2.starts_with(&metadir);
                if is_hardlink2 {
                    return Ok(());
                }
            }
        }

        if let Some((i, j)) = syscall.renames_metadata {
            let i = i as usize;
            let j = j as usize;
            let path1 = save_paths[i].as_ref().unwrap().as_path();
            let path2 = save_paths[j].as_ref().unwrap().as_path();
            let path1 = self.get_metadata_path(path1)?;
            let path2 = self.get_metadata_path(path2)?;
            if let (Some(path1), Some(path2)) = (path1, path2) {
                std::fs::rename(path1, path2).map_err(SysAugError::RenameMetadata)?;
            }
        }
        Ok(())
    }

    /// handles both symlinks and hardlinks
    fn on_link_syscall_exit(
        &self,
        syscall: &SyscallInfo,
        _args: &[usize],
        save_paths: &[Option<PathBuf>],
    ) -> Result<(), SysAugError> {
        if let Some((_, i)) = syscall.creates_symlink {
            let i = i as usize;
            if let Some(path) = save_paths[i].as_ref() {
                self.save_metadata_for_file(path, |x| x.is_symlink = Some(true))?;
            }
        }
        if let Some((_, i)) = syscall.creates_hardlink {
            let i = i as usize;
            if let Some(path) = save_paths[i].as_ref() {
                self.increment_hardlink_counter(path)?;
            }
        }
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
        future_builder: &StrongWeakBuilder<F>,
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
        let _ = krsm::downgrade(&future_builder).await;

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
        future_builder: &StrongWeakBuilder<F>,
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
                "Chmod syscall doesn't have sets_file_perms",
            ))?;
        state.write_arg(
            *position as usize,
            self.consts.config.rootfs.host_file_perms,
        );

        // Resume system call, and drop the WeakFutureGuard
        let _ = krsm::downgrade(&future_builder).await;

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
        future_builder: &StrongWeakBuilder<F>,
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
        let _ = krsm::downgrade(&future_builder).await;

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

    async fn on_stat_syscall_exit(
        &self,
        syscall: &SyscallInfo,
        orig_args: &[usize],
        save_paths: &[Option<PathBuf>],
    ) -> Result<(), SysAugError> {
        let maybe_stat_path =
            save_paths
                .iter()
                .find_map(|x| x.as_ref())
                .ok_or(SysAugError::SyscallMissingField(
                    "stat syscalls don't have a corresponding path/fd to read from",
                ));

        if let Some(position) = &syscall.stat_buf_position {
            let path = maybe_stat_path?.as_path();
            let addr = orig_args[*position as usize];
            self.replace_statbuf_result::<libc::stat>(addr, path)
                .await?;
        } else if let Some(position) = &syscall.stat_legacy_buf_position {
            let path = maybe_stat_path?.as_path();
            let addr = orig_args[*position as usize];

            #[cfg(target_pointer_width = "32")]
            {
                self.replace_statbuf_result::<StatLegacy>(addr, path)
                    .await?;
            }
            #[cfg(target_pointer_width = "64")]
            {
                self.replace_statbuf_result::<libc::stat>(addr, path)
                    .await?;
            }
        } else if let Some(position) = &syscall.stat64_buf_position {
            let path = maybe_stat_path?.as_path();
            let addr = orig_args[*position as usize];
            self.replace_statbuf_result::<libc::stat64>(addr, path)
                .await?;
        } else if let Some(position) = &syscall.statx_buf_position {
            let path = maybe_stat_path?.as_path();
            let addr = orig_args[*position as usize];
            self.replace_statbuf_result::<libc::statx>(addr, path)
                .await?;
        }
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
            let action = self
                .get_mod_path(syscall, orig_path, PathAction::None, true)
                .await?;
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

    async fn replace_statbuf_result<T>(&self, addr: usize, path: &Path) -> Result<(), SysAugError>
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
