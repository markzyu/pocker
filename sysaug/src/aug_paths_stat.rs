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

use crate::aug_paths_common::{AugmentState, FILE_PERMS_MASK, StrongWeakBuilder, StrongWeakOutput};
use crate::common::{SysAugError, SyscallInfo};
use crate::handler_async::{AsyncTraceeHandler, get_mem_helper};
use pocker_ptrace::{read_bytes_to_fixed_sized_objs, write_fixed_sized_objs_to_tracee};
use std::path::Path;
use std::pin::Pin;
use tracing::{Level, event};

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub(crate) async fn augment_stat<F: Future<Output = StrongWeakOutput>>(
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
