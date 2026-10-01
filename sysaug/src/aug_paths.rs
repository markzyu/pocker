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
    GenericPurposeRegs, MemHelpers, read_bytes_to_fixed_sized_objs, read_bytes_to_structs, setregs,
    write_fixed_sized_objs_to_tracee, write_structs_to_tracee,
};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tracing::{Level, event};

/// Per Linux inode.7 documentation, stx_mode needs a mask, if we only want to manipulate chmod
const FILE_PERMS_MASK: usize = 0o7777;

const EACCES: usize = -libc::EACCES as usize;
const EEXIST: usize = -libc::EEXIST as usize;

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub async fn augment_sys_paths(
        &self,
        mut orig_regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let pid = self.pid;
        let ptrace_client = &self.ptrace_client;
        let MemHelpers {
            read_bytes_until_zero,
            ..
        } = get_mem_helper();

        // Translate paths from host namespace to tracee namespace
        let copy_regs = orig_regs.clone();
        let read_args = [
            orig_regs.arg0,
            orig_regs.arg1,
            orig_regs.arg2,
            orig_regs.arg3,
            orig_regs.arg4,
        ];
        let write_args = [
            &mut orig_regs.arg0,
            &mut orig_regs.arg1,
            &mut orig_regs.arg2,
            &mut orig_regs.arg3,
            &mut orig_regs.arg4,
        ];
        let mut need_write_regs = false;
        let mut need_write_paths: usize = 0;
        let mut need_skip_syscall: Option<usize> = None;
        let mut save_paths: [Option<PathBuf>; 4] = Default::default();
        for i in 0..read_args.len() {
            let check_bit: usize = 1 << i;
            if (check_bit & syscall.path_positions) == 0 {
                continue;
            }
            let arg_i = read_args[i];
            if arg_i == 0 {
                continue;
            }

            let dirfd_path = self
                .get_dirfd_path(&copy_regs, syscall, i)?
                .unwrap_or("".into());

            // Read orig_path from registers
            // TODO: This can cause buffer overflow if tracee is malicious.
            let path_bytes =
                ptrace_client.execute(move || (read_bytes_until_zero)(pid, arg_i))??;
            let orig_path_buf = Self::path_from_bytes(path_bytes)?;

            // Calculate path_action, and maybe update tracee
            let path_action = self
                .calc_real_path(&orig_path_buf, syscall, &read_args)
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
                    self.do_skip_syscall(-libc::ELOOP as usize).await?;
                    return Ok(());
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

        // Handle filefd_position (This overwrites all other save_paths)
        if let Some(position) = syscall.filefd_position {
            save_paths[0] = Some(
                pocker_procfs::getfd_path(pid, read_args[position as usize] as isize)?
                    .unwrap_or("".into()),
            );
            event!(Level::INFO, "filefd path {:?}", &save_paths[0]);
            // There is no need to calc_real_path, because pocker cannot override real fds
        }

        // Handle getdents (make the buffer seem smaller)
        if syscall.getdents_bits.is_some() {
            *write_args[2] /= 2;
            need_write_regs = true;
        }

        // Delete metadata before unlink & rmdir
        if syscall.deletion_type.is_some() {
            let ref_save_paths = &save_paths;
            for path in ref_save_paths.iter().flatten() {
                self.delete_metadata_for_file(path)?;
            }
        }

        // Handle reads of hardlinks
        let maybe_path = save_paths.iter_mut().find_map(|x| x.as_mut());
        if syscall.should_follow_hardlink
            && let Some(path) = maybe_path
        {
            if let Some(meta) = self.read_metadata_for_file(path)? {
                if meta.hardlink_counter.is_some() {
                    // Resolve the actual path of the hardlink
                    *path = path.canonicalize().map_err(SysAugError::StatHardlinkIO)?;
                    let i = save_paths.iter().position(|x| x.is_some()).unwrap();
                    need_write_paths |= 1 << i;

                    // Set dirfd to AT_FDCWD to avoid ELOOP on some Linux
                    if syscall.dirfd_precedes_path {
                        *write_args[i - 1] = libc::AT_FDCWD as usize;
                    }

                    if let Some(j) = syscall.dirfd_position {
                        *write_args[j as usize] = libc::AT_FDCWD as usize;
                    }
                }
            }
        }

        // Replace the arguments for chmod and chown, according to Rootfs configs
        if &syscall.sets_file_perms == &Some(PermType::Chown) {
            let position = &syscall
                .file_perms_position
                .ok_or(SysAugError::SyscallMissingField(
                    "Chmod syscall doesn't have sets_file_perms",
                ))?;
            *write_args[*position as usize] = self.consts.config.rootfs.host_uid;
            *write_args[*position as usize + 1] = self.consts.config.rootfs.host_gid;
            need_write_regs = true;
        } else if syscall.sets_file_perms.is_some() {
            let position = &syscall
                .file_perms_position
                .ok_or(SysAugError::SyscallMissingField(
                    "Chmod syscall doesn't have sets_file_perms",
                ))?;
            *write_args[*position as usize] = self.consts.config.rootfs.host_file_perms;
            need_write_regs = true;
        }

        // Create hardlinks by (1) moving the original file (2) creating two symlinks (3) skip system call
        if let Some((i, j)) = syscall.creates_hardlink
            && let Some(metadir) = self.get_metadata_dir()
        {
            let i = i as usize;
            let j = j as usize;
            if let Some(path) = save_paths[i].as_ref()
                && path.exists()
            {
                let target_path = if path.starts_with(&metadir) {
                    path.clone()
                } else {
                    let links_dir = metadir.join("links");
                    let uuid = uuid::Uuid::new_v4().to_string();
                    let new_meta = links_dir.join(format!("{}.json", &uuid));
                    let target_path = links_dir.join(uuid);

                    // First, move the metadata
                    std::fs::create_dir_all(&links_dir).map_err(SysAugError::CreateHardlinkIO)?;
                    if let Some(old_meta) = self.get_metadata_path(path)? {
                        let _ = std::fs::rename(&old_meta, &new_meta)
                            .map_err(SysAugError::CreateHardlinkIO)
                            .map_err(display_err);
                    };

                    // Then, move the link content
                    std::fs::rename(path, &target_path).map_err(SysAugError::CreateHardlinkIO)?;

                    // Then, setup symlinks
                    symlink(&target_path, path).map_err(SysAugError::CreateHardlinkIO)?;
                    self.increment_hardlink_counter(path)?;
                    target_path
                };

                let result_path = save_paths[j].as_ref().unwrap();
                let rootfs_path = self.consts.args.rootfs.as_ref().unwrap();
                if !result_path.starts_with(rootfs_path) {
                    need_skip_syscall.replace(EACCES);
                } else if result_path.exists() {
                    need_skip_syscall.replace(EEXIST);
                } else {
                    symlink(&target_path, result_path).map_err(SysAugError::CreateHardlinkIO)?;
                    need_skip_syscall.replace(0);
                }
            }
        }

        // Write new paths and args into register
        for i in 0..read_args.len() {
            let check_bit: usize = 1 << i;
            if (need_write_paths & check_bit) == 0 {
                continue;
            }
            if let Some(path) = save_paths[i].as_ref() {
                *write_args[i] = self.tracee_stack_append_path(path.clone())?;
                need_write_regs = true;
            }
        }
        if need_write_regs && need_skip_syscall.is_none() {
            // Update registers, before real syscall
            ptrace_client.execute(move || setregs(pid, orig_regs))??;
        }

        let (regs, retval) = if let Some(retval) = need_skip_syscall {
            self.do_skip_syscall(retval).await?;
            (None as Option<GenericPurposeRegs>, retval)
        } else {
            let regs = self.do_resume_syscall().await?;
            let retval = regs.syscall_retval();
            (Some(regs), retval)
        };
        let retval = retval as isize;

        self.on_chmod_chown_syscall_exit(syscall, &read_args, &save_paths)?;

        if retval < 0 {
            return Ok(());
        }

        self.on_stat_syscall_exit(syscall, &read_args, &save_paths)
            .await?;
        self.on_link_syscall_exit(syscall, &read_args, &save_paths)?;
        self.on_rename_syscall_exit(syscall, &read_args, &save_paths)?;

        if retval == 0 {
            return Ok(());
        }

        if let Some(regs) = regs {
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
        }
        Ok(())
    }

    /// Rename metadata as well.
    fn on_rename_syscall_exit(
        &self,
        syscall: &SyscallInfo,
        _args: &[usize],
        save_paths: &[Option<PathBuf>],
    ) -> Result<(), SysAugError> {
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

    fn on_chmod_chown_syscall_exit(
        &self,
        syscall: &SyscallInfo,
        read_args: &[usize],
        save_paths: &[Option<PathBuf>],
    ) -> Result<(), SysAugError> {
        if let Some(PermType::Chmod) = &syscall.sets_file_perms {
            let position = &syscall
                .file_perms_position
                .ok_or(SysAugError::SyscallMissingField(
                    "Chmod syscall doesn't have sets_file_perms",
                ))?;
            let new_mod = read_args[*position as usize];
            for path in save_paths.iter().flatten() {
                event!(Level::INFO, "Handling chmod: {:?}, {:b}", &path, new_mod);
                self.save_metadata_for_file(path, |x| x.chmod = Some(new_mod & FILE_PERMS_MASK))?;
            }
        }
        if let Some(PermType::ChmodOnCreation) = &syscall.sets_file_perms {
            let flags_position = &syscall.flags.ok_or(SysAugError::SyscallMissingField(
                "ChmodOnCreation syscall doesn't have flags",
            ))?;
            let perms_position =
                &syscall
                    .file_perms_position
                    .ok_or(SysAugError::SyscallMissingField(
                        "ChmodOnCreation syscall doesn't have sets_file_perms",
                    ))?;
            let flags = read_args[*flags_position];
            if flags & (libc::O_CREAT as usize) != 0 {
                let new_mod = read_args[*perms_position as usize];
                for path in save_paths.iter().flatten() {
                    event!(Level::INFO, "Handling chmod: {:?}, {:b}", &path, new_mod);
                    self.save_metadata_for_file(path, |x| {
                        x.chmod = Some(new_mod & FILE_PERMS_MASK)
                    })?;
                }
            }
        }
        if let Some(PermType::Chown) = &syscall.sets_file_perms {
            let position = &syscall
                .file_perms_position
                .ok_or(SysAugError::SyscallMissingField(
                    "Chown syscall doesn't have sets_file_perms",
                ))?;
            let new_owner = read_args[*position as usize];
            let new_group = read_args[(*position + 1) as usize];
            for path in save_paths.iter().flatten() {
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
            }
        }
        Ok(())
    }

    async fn on_stat_syscall_exit(
        &self,
        syscall: &SyscallInfo,
        read_args: &[usize],
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
            let addr = read_args[*position as usize];
            self.replace_statbuf_result::<libc::stat>(addr, path)
                .await?;
        } else if let Some(position) = &syscall.stat_legacy_buf_position {
            let path = maybe_stat_path?.as_path();
            let addr = read_args[*position as usize];

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
            let addr = read_args[*position as usize];
            self.replace_statbuf_result::<libc::stat64>(addr, path)
                .await?;
        } else if let Some(position) = &syscall.statx_buf_position {
            let path = maybe_stat_path?.as_path();
            let addr = read_args[*position as usize];
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
