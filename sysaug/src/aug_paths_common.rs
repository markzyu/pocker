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
use pocker_ptrace::{GenericPurposeRegs, MemHelpers, setregs};
use std::cell::RefCell;
use std::path::PathBuf;
use tracing::{Level, event};

/// Per Linux inode.7 documentation, stx_mode needs a mask, if we only want to manipulate chmod
pub(crate) const FILE_PERMS_MASK: usize = 0o7777;

// The StrongFuture will output (regs after system call, retval of system call)
pub(crate) type StrongWeakOutput = Result<(GenericPurposeRegs, isize), SysAugError>;
pub(crate) type StrongWeakBuilder<F> = krsm::StrongWeakBuilder<StrongWeakOutput, F>;

// How many system call arguments are considered
const ARGS_LEN: usize = 5;

// This is a helper struct that holds registers and parsed paths during syscall-entry
pub(crate) struct AugmentState {
    entry_regs: RefCell<GenericPurposeRegs>,
    pub(crate) orig_args: [usize; ARGS_LEN],

    save_paths: RefCell<[Option<PathBuf>; ARGS_LEN]>,

    need_write_regs: RefCell<bool>,
    // This is a bitmask for bits in 0..ARGS_LEN
    need_write_paths: RefCell<usize>,
    // This stores the system call return value if skipped
    need_skip_syscall: RefCell<Option<usize>>,
}

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    // Parse register upon syscall-entry, into aug_path::AugmentState
    pub(crate) fn _aug_paths_do_parse_state(
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

    pub(crate) fn _aug_paths_do_write_registers(&self, state: &AugmentState) -> Result<(), SysAugError> {
        let pid = self.pid;
        let ptrace_client = &self.ptrace_client;

        // Write new paths into register
        let need_skip_syscall = { *state.need_skip_syscall.borrow() };
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
}

impl AugmentState {
    pub(crate) fn write_arg(&self, idx: usize, val: usize) {
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

    pub(crate) fn set_skip_syscall(&self, retval: usize) {
        let mut guard = self.need_skip_syscall.borrow_mut();
        guard.replace(retval);
    }

    pub(crate) fn for_saved_path(
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
    pub(crate) fn first_saved_path_mut(
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
    pub(crate) fn saved_path_idx(
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
    pub(crate) fn saved_path_pair(
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

    pub(crate) fn is_skip_syscall(&self) -> Option<usize> {
        *self.need_skip_syscall.borrow()
    }
}