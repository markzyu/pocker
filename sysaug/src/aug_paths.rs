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

use crate::aug_paths_common::{AugmentState, StrongWeakBuilder, StrongWeakOutput, FILE_PERMS_MASK};
use crate::common::{SysAugError, SyscallInfo};
use crate::handler_async::AsyncTraceeHandler;
use crate::PermType;
use pocker_ptrace::{
    GenericPurposeRegs, getregs
};
use std::pin::{Pin, pin};
use tracing::{Level, event};

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
        if let Some(retval) = state.is_skip_syscall() {
            self.do_skip_syscall(retval).await?;
            return Ok(());
        }

        // Run synchronous augments first
        self.augment_deletion(syscall, &state)?;
        self.augment_hardlink_following(syscall, &state)?;

        let syscall_future = async {
            // Perform system call
            self._aug_paths_do_write_registers(&state)?;

            if let Some(retval) = state.is_skip_syscall() {
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
                self.augment_hardlink_rename(strong_pinned.as_ref(), syscall, &state),
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
}