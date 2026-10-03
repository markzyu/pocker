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
use crate::common::{SysAugError, SyscallInfo};
use crate::handler_async::AsyncTraceeHandler;
use crate::display_err;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::pin::Pin;

const EACCES: usize = -libc::EACCES as usize;
const EEXIST: usize = -libc::EEXIST as usize;

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    pub(crate) async fn augment_symlink_creation<F: Future<Output = StrongWeakOutput>>(
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

    pub(crate) async fn augment_hardlink_creation<F: Future<Output = StrongWeakOutput>>(
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
    pub(crate) fn augment_hardlink_following(
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

    pub(crate) async fn augment_hardlink_rename<F: Future<Output = StrongWeakOutput>>(
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
}