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

use crate::aug_paths_common::{AugmentState, StrongWeakBuilder, StrongWeakOutput};
use crate::common::{PathAction, SysAugError, SyscallInfo};
use crate::handler_async::{AsyncTraceeHandler, get_mem_helper};
use pocker_ptrace::{
    GenericPurposeRegs, read_bytes_to_structs,
    setregs, write_structs_to_tracee,
};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::pin::Pin;
use tracing::{Level, event};

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub(crate) async fn augment_getdents<F: Future<Output = StrongWeakOutput>>(
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