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

use crate::common::{OverlayFileType, PathAction, SysAugError, SyscallInfo, get_metadata_dir};
use crate::config::{RenameAccessMode, RenameConfig};
use crate::fs::FileSystem;
use std::collections::HashSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use tracing::{Level, event};

impl FileSystem {
    // -----------------------------------------------------------------------------
    // ------------------------ Path Modifications (Chroot) ------------------------
    // -----------------------------------------------------------------------------

    /// Calculates the host side path of a file according to its guest side path.
    ///
    /// Note: If you have a dirfd, please convert it to the guest path, using
    /// [FileSystem::calc_guest_path_from_dirfd]
    pub fn calc_real_path(
        &self,
        guest_path: &Path,
        syscall: &SyscallInfo,
        args: &[usize],
    ) -> Result<PathAction, SysAugError> {
        let result = self.calc_real_path_recurse(guest_path, syscall, HashSet::new(), args)?;
        event!(
            Level::DEBUG,
            "Following symlink {:?} -> {:?}",
            guest_path,
            &result
        );
        Ok(result)
    }

    fn calc_real_path_simple(
        &self,
        orig_path: &Path,
        syscall: &SyscallInfo,
        args: &[usize],
    ) -> Result<PathAction, SysAugError> {
        let mut new_path = PathAction::None;
        let prefix_maybe = self.path_prefix.borrow();
        let exclude_list = self.path_prefix_excludes.borrow();
        if !exclude_list.iter().any(|x| orig_path.starts_with(x)) {
            if let Some(prefix) = prefix_maybe.as_ref() {
                if orig_path.is_absolute() {
                    let val = prefix.as_path().join(orig_path.strip_prefix("/").unwrap());
                    new_path = PathAction::Override(val);
                }
            }
        }

        self.get_mod_path(syscall, args, orig_path, new_path, false)
    }

    // Calculate real path of file + following symlinks that use fake paths
    fn calc_real_path_recurse(
        &self,
        orig_path: &Path,
        syscall: &SyscallInfo,
        mut visited: HashSet<PathBuf>,
        args: &[usize],
    ) -> Result<PathAction, SysAugError> {
        visited.insert(orig_path.into());
        let action = self.calc_real_path_simple(orig_path, syscall, args)?;
        if let PathAction::Override(real_path) = &action {
            let result = self.calc_follow_symlink(real_path, syscall, &mut visited, args)?;
            match result {
                Err(false) => return Ok(action),
                Err(true) => return Ok(PathAction::ELOOP),
                Ok(link) => {
                    let new_action =
                        self.calc_real_path_recurse(link.as_path(), syscall, visited, args)?;
                    if new_action == PathAction::None {
                        return Ok(PathAction::Override(link));
                    } else {
                        return Ok(new_action);
                    }
                }
            }
        } else if action == PathAction::None {
            let exclude_list = self.path_prefix_excludes.borrow();
            if exclude_list.iter().any(|x| orig_path.starts_with(x)) {
                // We should NOT follow symlink for paths excluded from Paths augmentation
                return Ok(PathAction::None);
            }

            let orig_path_buf: PathBuf = orig_path.into();
            let result = self.calc_follow_symlink(&orig_path_buf, syscall, &mut visited, args)?;
            match result {
                Err(false) => return Ok(PathAction::None),
                Err(true) => return Ok(PathAction::ELOOP),
                Ok(link) => {
                    let new_action =
                        self.calc_real_path_recurse(link.as_path(), syscall, visited, args)?;
                    if new_action == PathAction::None {
                        return Ok(PathAction::Override(link));
                    } else {
                        return Ok(new_action);
                    }
                }
            }
        }
        Ok(action)
    }

    /// Follow only one layer of symlink without doing translations (Returns Ok(Err(true)) if loop)
    fn calc_follow_symlink(
        &self,
        real_path: &PathBuf,
        syscall: &SyscallInfo,
        visited: &mut HashSet<PathBuf>,
        args: &[usize],
    ) -> Result<Result<PathBuf, bool>, SysAugError> {
        if syscall.dont_follow_symlink {
            return Ok(Err(false));
        } else if let (Some(flag), Some(flag_reg)) =
            (syscall.flag_dont_follow_symlink, syscall.flags)
        {
            if (args[flag_reg] & flag) != 0 {
                return Ok(Err(false));
            }
        }

        if let Ok(real_path_str) = real_path.clone().into_os_string().into_string() {
            if real_path_str.contains("/proc/self") {
                let new_part = format!("/proc/{}", self.pid);
                let new_path_str = real_path_str.replace("/proc/self", &new_part);
                let new_path_buf = PathBuf::from(new_path_str);
                return self.calc_follow_symlink(&new_path_buf, syscall, visited, args);
            }
        }

        if let Some(link) = Self::_read_symlink(real_path)? {
            if let Some(metadir) = get_metadata_dir(self.consts.args.rootfs.as_ref())
                && let Ok(link) = link.canonicalize()
                && link.starts_with(&metadir)
            {
                return Ok(Err(false));
            }
            if visited.contains(&link) {
                return Ok(Err(true));
            }
            return Ok(Ok(link));
        }
        Ok(Err(false))
    }

    // There are SysAugConfig configurations that can "modify" a guest/host path. This function applies them.
    // reverse: false = generating real paths on disk, true = generating fake paths from container
    // perspective
    pub fn get_mod_path(
        &self,
        syscall: &SyscallInfo,
        args: &[usize],
        orig_path: &Path,
        initial_override: PathAction,
        reverse: bool,
    ) -> Result<PathAction, SysAugError> {
        let curr_path = match &initial_override {
            PathAction::Override(path) => path.as_path(),
            _ => orig_path,
        };
        let bytes_str = curr_path.as_os_str().as_encoded_bytes();
        let rename_map = if reverse {
            self.rename_guest_paths.borrow()
        } else {
            self.rename_host_paths.borrow()
        };
        for config in rename_map.iter() {
            if !config.regex.is_match(bytes_str) {
                continue;
            }
            let Some(ref replacement) = config.replacement else {
                return Ok(PathAction::HidePath);
            };

            // Calculate the new path
            let replacement_bytes = replacement.as_bytes();
            let replacement = if config.should_replace_all {
                config.regex.replace_all(bytes_str, replacement_bytes)
            } else {
                config.regex.replace(bytes_str, replacement_bytes)
            };
            let os_str = OsString::from_vec(replacement.into());
            let new_path: PathBuf = os_str.into();

            // Handle CopyOnWrite mode
            if !reverse {
                let is_cow = self._check_cow(config, syscall, args, curr_path, &new_path)?;
                if is_cow == Some(true) {
                    return Ok(initial_override);
                } else if is_cow == None {
                    continue;
                }
            }

            // Handle Default mode
            return Ok(PathAction::Override(new_path));
        }
        Ok(initial_override)
    }

    /// This is a helper function for `get_mod_path`.
    ///
    /// It checks a specific syscall, and a path to see whether this
    /// access is writing to a valid file such that it can be Copy on Write
    ///
    /// path is the original host path.
    /// real_path is the host path if mapped via the current overlayfs
    ///
    /// Returns: Some(true) if writing to a copy at `path`
    /// Returns: Some(false) if reading a file that exists at `real_path`
    /// Returns: None if neither applies (this layer doesn't contain the file)
    fn _check_cow(
        &self,
        config: &RenameConfig,
        syscall: &SyscallInfo,
        args: &[usize],
        path: &Path,
        real_path: &PathBuf,
    ) -> Result<Option<bool>, SysAugError> {
        if config.access_mode != RenameAccessMode::CopyOnWrite {
            return Ok(Some(false));
        }

        if !real_path.exists() {
            return Ok(None);
        }

        let real_path_is_dir = !real_path.is_symlink() && real_path.is_dir();
        if real_path_is_dir && syscall.deletion_type.is_none() {
            // Check the cow metadata of directory content
            // But, enumerate the directory as if it's on the rootfs, not as overlays
            // And, mark the directory itself as a CoW file so that whiteouts work
            let p = path.to_string_lossy().to_string();
            let paths = _check_cow_directory(path, real_path)
                .map_err(|e| SysAugError::MountCannotMergeDirectory(e, p))?;

            self._save_overlay_metadata(path, real_path, OverlayFileType::CoW)?;

            for (child_path, child_new_path) in paths {
                if !child_new_path.is_symlink() && child_new_path.is_dir() {
                    let child_overlay_type = if let Some(meta) = self.read_metadata(&child_path)? {
                        meta.overlay_type
                    } else {
                        None
                    };
                    if child_overlay_type == Some(OverlayFileType::CoW) {
                        continue;
                    }

                    let p2 = child_path.to_string_lossy().to_string();
                    std::fs::create_dir_all(child_path)
                        .map_err(|e| SysAugError::MountCannotMergeDirectory(e, p2))?;

                    // Do not recurse into subdirectories
                    continue;
                }
                self._check_cow(config, syscall, args, &child_path, &child_new_path)?;
            }
            return Ok(None);
        }

        let overlay_type = if let Some(meta) = self.read_metadata(path)? {
            meta.overlay_type
        } else {
            None
        };

        if overlay_type.is_some() && !path.exists() {
            // Right now the only way to whiteout a file is to delete the content
            // while keeping the metadata
            return Ok(None);
        }

        let mut is_cow = false;
        if path.exists() && overlay_type != Some(OverlayFileType::Placeholder) {
            is_cow = true;
        } else if syscall.writes_file || syscall.deletion_type.is_some() {
            is_cow = true;
        } else if let Some(flag_position) = syscall.flags
            && let Some(flag) = syscall.flag_writes_file
            && (args[flag_position] & flag) != 0
        {
            is_cow = true;
        }

        // Create the copy
        let has_not_copied = !path.exists() || overlay_type == Some(OverlayFileType::Placeholder);
        if is_cow && has_not_copied {
            let p = path.to_string_lossy().to_string();
            std::fs::copy(real_path, path)
                .map_err(|e| SysAugError::MountCannotCopyOnWrite(e, p))?;
        }
        if is_cow {
            self._save_overlay_metadata(path, real_path, OverlayFileType::CoW)?;
        }

        // Or, create the placeholder
        if !is_cow && !path.exists() && overlay_type != Some(OverlayFileType::CoW) {
            let p = path.to_string_lossy().to_string();
            if real_path_is_dir {
                std::fs::create_dir_all(path)
                    .map_err(|e| SysAugError::MountCannotCreatePlaceholder(e, p))?;
            } else {
                if let Some(parent) = path.parent() {
                    let p2 = parent.to_string_lossy().to_string();
                    std::fs::create_dir_all(parent)
                        .map_err(|e| SysAugError::MountCannotCreatePlaceholder(e, p2))?;
                }
                std::fs::write(path, "")
                    .map_err(|e| SysAugError::MountCannotCreatePlaceholder(e, p))?;
            }
            self._save_overlay_metadata(path, real_path, OverlayFileType::Placeholder)?;
        }

        Ok(Some(is_cow))
    }

    fn _save_overlay_metadata(
        &self,
        path: &Path,
        real_path: &Path,
        overlay_type: OverlayFileType,
    ) -> Result<(), SysAugError> {
        let guard = self.metadata_layers.borrow();
        let mut maybe_rootfs: Option<PathBuf> = None;
        for layer in guard.iter() {
            if real_path.starts_with(&layer.source_path) {
                maybe_rootfs = Some(layer.source_path.clone());
                break;
            }
        }

        // Initialize metadata by copying from the source layer
        if let Some(src) = Self::_resolve_metadata_path(maybe_rootfs.as_ref(), real_path)?
            && src.exists()
            && let Some(dest) =
                Self::_resolve_metadata_path(self.consts.args.rootfs.as_ref(), path)?
            && !dest.exists()
        {
            let p1 = dest.to_string_lossy().to_string();
            let parent = dest.parent().unwrap();
            let p2 = parent.to_string_lossy().to_string();
            std::fs::create_dir_all(parent)
                .map_err(|e| SysAugError::MountCannotCopyOnWrite(e, p2))?;
            std::fs::copy(&src, &dest).map_err(|e| SysAugError::MountCannotCopyOnWrite(e, p1))?;
        }

        self.save_metadata(path, |x| {
            if overlay_type == OverlayFileType::CoW {
                x.hardlink_counter = None;
            }
            x.overlay_type = Some(overlay_type);
        })?;
        Ok(())
    }

    /// Consider dirfd (which is a host path) and return the guest path, or None if not found.
    ///
    /// For this to work properly,
    ///
    /// * The `dirfd_path` should be the current workdir if syscall has no dirfd.
    /// * The `dirfd_path` should be the current workdir if dirfd is AT_FDCWD.
    /// * The `dirfd_path` should be Some("/absolute/path") for files.
    /// * The `dirfd_path` should be None for pipes and other non-file FDs.
    ///
    /// The resulting "guest" path will not be applied with the `rename_guest_paths` config.
    /// This function is meant to provide the path input for [FileSystem::calc_real_path]. That
    /// function will then apply `rename_host_paths` to the final result.
    pub fn calc_guest_path_from_dirfd(
        &self,
        dirfd_path: &Option<PathBuf>,
        orig_path: &PathBuf,
    ) -> Option<PathBuf> {
        // Consider dirfd
        let empty_path = PathBuf::from("");
        let dirfd_path = dirfd_path.as_ref().unwrap_or(&empty_path);
        let orig_path = if orig_path.as_os_str().is_empty() {
            // In case of AT_EMPTY_PATH/empty relative path, just pass dirfd_path only
            dirfd_path.clone()
        } else {
            // Note that, if orig_path is absolute, then dirfd_path is ignored
            dirfd_path.join(&orig_path)
        };

        if orig_path.as_os_str().is_empty() {
            // In case of AT_EMPTY_PATH with a non-file FD, pass the empty string as is
            return Some(orig_path);
        }

        // If the path is not absolute, then inform downstream of ENOENT
        if orig_path.is_relative() {
            return None;
        }
        let Ok(orig_path) = std::path::absolute(&orig_path) else {
            return None;
        };

        // Strip the prefix if it matches
        let path_prefix = {
            let default = PathBuf::from("/");
            let guard = self.path_prefix.borrow();
            guard.as_ref().unwrap_or(&default).clone()
        };
        if let Ok(stripped) = orig_path.strip_prefix(path_prefix) {
            let root = PathBuf::from("/");
            return Some(root.join(stripped));
        }

        // Otherwise, return the path as is
        // (It could match a rename rule or an exclusion rule)
        Some(orig_path)
    }
}

// path is the original host path. new_path is the overlay path.
fn _check_cow_directory(
    path: &Path,
    new_path: &Path,
) -> Result<Vec<(PathBuf, PathBuf)>, std::io::Error> {
    let mut paths: Vec<(PathBuf, PathBuf)> = Vec::new();
    std::fs::create_dir_all(path)?;
    let contents = std::fs::read_dir(new_path)?;
    for entry in contents {
        let filename = entry?.file_name();
        let child_path = path.join(&filename);
        let child_new_path = new_path.join(&filename);
        paths.push((child_path, child_new_path));
    }
    Ok(paths)
}
