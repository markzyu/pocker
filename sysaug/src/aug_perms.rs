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

use crate::common::{PermsMode, SysAugError, SyscallInfo};
use crate::config::walk_res_bits;
use crate::handler_async::AsyncTraceeHandler;
use pocker_ptrace::GenericPurposeRegs;
use tracing::{Level, event};

const EINVAL: isize = nix::errno::Errno::EINVAL as isize;

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub async fn augment_sys_perms(
        &self,
        orig_regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let should_skip = self.do_sysenter_perms(&orig_regs, syscall)?;
        if let Some(retval) = should_skip {
            return self.do_skip_syscall(retval).await;
        }
        let regs = self.do_resume_syscall().await?;
        self.do_sysexit_perms(regs, syscall)?;
        Ok(())
    }

    /// Returns Some(retval) if the syscall should be skipped. Returns None if it should run.
    pub fn do_sysenter_perms(
        &self,
        regs: &GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<Option<usize>, SysAugError> {
        let possible_args = &[regs.arg0, regs.arg1, regs.arg2];
        if !syscall.is_setter || self.consts.args.perms_mode == PermsMode::Passthrough {
            // Getters don't need overrides during sysenter
            Ok(None)
        } else if let Some(resf_bit) = syscall.resf_bit {
            let proposed_id = regs.arg0;
            if (proposed_id as i32) < 0 {
                return Ok(Some((-EINVAL) as usize));
            }

            let mut guard = self.perms_ids.borrow_mut();
            let final_id = self.handle_setid(syscall, proposed_id)?;
            guard[resf_bit as usize] = Some(final_id);
            Ok(Some(0))
        } else if syscall.res_bits > 0 {
            let mut retval: isize = 0;
            walk_res_bits(syscall, &self.perms_ids, |i, _| {
                let proposed_id = possible_args[i];
                if (proposed_id as i32) < 0 {
                    retval = -EINVAL;
                }
                Ok(())
            })?;
            walk_res_bits(syscall, &self.perms_ids, |i, val| {
                if retval > 0 {
                    let proposed_id = possible_args[i];
                    let final_id = self.handle_setid(syscall, proposed_id)?;
                    *val = Some(final_id);
                }
                Ok(())
            })?;
            Ok(Some(retval as usize))
        } else {
            Ok(None)
        }
    }

    pub fn do_sysexit_perms(
        &self,
        regs: GenericPurposeRegs,
        syscall: &SyscallInfo,
    ) -> Result<(), SysAugError> {
        let possible_args = &[regs.arg0, regs.arg1, regs.arg2];
        if syscall.is_setter || self.consts.args.perms_mode == PermsMode::Passthrough {
            // Setters don't need overrides during sysexit
        } else if let Some(resf_bit) = syscall.resf_bit {
            let guard = self.perms_ids.borrow();
            if let Some(val) = guard[resf_bit as usize].as_ref() {
                event!(
                    Level::INFO,
                    "Writing id {} to return value of {}",
                    *val,
                    syscall.name()
                );
                self.write_retval(regs.clone(), *val)?;
            }
        } else if syscall.res_bits > 0 {
            // Multi-getters could fail. And we should let them fail.
            if regs.syscall_retval() == 0 {
                walk_res_bits(syscall, &self.perms_ids, |i, val| {
                    let pid = self.pid;
                    let ptr_addr = possible_args[i];
                    if let Some(val) = val.clone() {
                        event!(
                            Level::INFO,
                            "Writing id {} to tracee pointer {:x}",
                            val,
                            ptr_addr
                        );
                        self.ptrace_client
                            .execute(move || pocker_ptrace::write(pid, ptr_addr, val))??;
                    }
                    Ok(())
                })?;
            }
        } else {
            // The default behavior is to let the unknown getter syscall succeed.
            if (regs.syscall_retval() as isize) < 0 {
                self.write_retval(regs, 0)?;
            }
        }
        Ok(())
    }

    fn handle_setid(
        &self,
        syscall: &SyscallInfo,
        proposed_id: usize,
    ) -> Result<usize, SysAugError> {
        if self.consts.args.perms_mode == PermsMode::RootOnly {
            if proposed_id >= usize::MAX / 2 {
                event!(
                    Level::INFO,
                    "Ignoring {} where id is negative",
                    syscall.name()
                );
                return Ok(0);
            }
        }
        event!(
            Level::INFO,
            "Setting id ({}) to {}",
            syscall.name(),
            proposed_id
        );
        Ok(proposed_id)
    }

    fn write_retval(&self, mut regs: GenericPurposeRegs, val: usize) -> Result<(), SysAugError> {
        regs.set_syscall_retval(val);
        let pid = self.pid;
        self.ptrace_client
            .execute(move || pocker_ptrace::setregs(pid, regs))??;
        Ok(())
    }
}
