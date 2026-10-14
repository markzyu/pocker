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

        if let Some(link) = self._read_symlink(real_path)? {
            if let Some(metadir) = self.get_metadata_dir()
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
                    self.save_metadata(orig_path, |x| {
                        x.is_cow = Some(true);
                    })?;
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
    /// new_path is the host path if mapped via the current overlayfs
    ///
    /// Returns: Some(true) if writing to a copy at `path`
    /// Returns: Some(false) if reading a file that exists at `new_path`
    /// Returns: None if neither applies (this layer doesn't contain the file)
    fn _check_cow(
        &self,
        config: &RenameConfig,
        syscall: &SyscallInfo,
        args: &[usize],
        path: &Path,
        new_path: &PathBuf,
    ) -> Result<Option<bool>, SysAugError> {
        if config.access_mode != RenameAccessMode::CopyOnWrite {
            return Ok(Some(false));
        }

        if !new_path.exists() {
            return Ok(None);
        }

        let mut is_cow = false;
        let meta_exists = self.get_metadata_path(path)?.is_some();
        if path.exists() || meta_exists {
            is_cow = true;
        } else if syscall.writes_file {
            is_cow = true;
        } else if let Some(flag_position) = syscall.flags
            && let Some(flag) = syscall.flag_writes_file
            && (args[flag_position] & flag) != 0
        {
            is_cow = true;
        }
        Ok(Some(is_cow))
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

#[cfg(test)]
#[serial_test::serial]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::syscalls::get_syscall;
    use crate::{SysAugArgs, TraceeHandlerConsts};
    use nix::unistd::Pid;
    use regex::bytes::Regex;

    // returns (fs, absolute path of staging dir / of rootfs)
    fn setup_with_config(config: SysAugConfig) -> (FileSystem, PathBuf) {
        let err = "Failed to setup tests";
        let staging_dir: PathBuf = PathBuf::from("../tests/fixtures/staging");
        let dir = staging_dir.as_path();
        if dir.exists() {
            std::fs::remove_dir_all(dir).expect(err);
        }
        std::fs::create_dir_all(dir).expect(err);
        std::fs::write(dir.join("x"), "123").expect(err);
        let staging_absolute = dir.canonicalize().expect(err);

        let consts = TraceeHandlerConsts {
            config,
            args: SysAugArgs {
                chroot: Some(staging_absolute.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let fs = FileSystem::new(consts, Pid::this()).unwrap();
        (fs, staging_absolute)
    }

    // returns (fs, absolute path of staging dir / of rootfs)
    fn setup() -> (FileSystem, PathBuf) {
        setup_with_config(SysAugConfig::default())
    }

    #[test]
    fn test_calc_real_path_of_file_on_rootfs() {
        let (fs, dir) = setup();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let path1 = PathBuf::from("/x");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(dir.join("x")));
    }

    #[test]
    fn test_calc_real_path_of_link_on_rootfs() {
        let (fs, dir) = setup();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/x", dir.join("y")).expect(err);

        let path1 = PathBuf::from("/y");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(dir.join("x")));
    }

    #[test]
    fn test_calc_real_path_of_link_to_host_path_would_double_wrap() {
        let (fs, dir) = setup();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink(dir.join("x"), dir.join("y")).expect(err);

        let dir_relative = dir.strip_prefix("/").expect(err);
        let expected = dir.join(dir_relative).join("x");

        let path1 = PathBuf::from("/y");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(expected));
    }

    #[test]
    fn test_calc_real_path_of_self_looping_symlink() {
        let (fs, dir) = setup();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/a", dir.join("a")).expect(err);

        let path1 = PathBuf::from("/a");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::ELOOP);
    }

    #[test]
    fn test_calc_real_path_of_looping_symlinks() {
        let (fs, dir) = setup();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/a", dir.join("b")).expect(err);
        std::os::unix::fs::symlink("/b", dir.join("a")).expect(err);

        let path1 = PathBuf::from("/a");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();

        let path2 = PathBuf::from("/b");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();

        assert_eq!(ans1, PathAction::ELOOP);
        assert_eq!(ans2, PathAction::ELOOP);
    }

    #[test]
    fn test_calc_real_path_of_symlink_not_followed() {
        let (fs, dir) = setup();
        let (maybe_syscall, _) = get_syscall(libc::SYS_readlinkat as usize);
        let syscall = maybe_syscall.expect("SYS_readlinkat syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/a", dir.join("b")).expect(err);
        std::os::unix::fs::symlink("/b", dir.join("a")).expect(err);

        let path1 = PathBuf::from("/a");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();

        let path2 = PathBuf::from("/b");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();

        assert_eq!(ans1, PathAction::Override(dir.join("a")));
        assert_eq!(ans2, PathAction::Override(dir.join("b")));
    }

    fn setup_with_rename_config() -> (FileSystem, PathBuf) {
        let config = SysAugConfig {
            rootfs: RootfsConfig {
                rename_host_paths: vec![RenameConfig {
                    regex: Regex::new(r"^(.*)/x$").unwrap(),
                    replacement: Some(String::from("$1/xy")),
                    should_replace_all: false,
                    access_mode: RenameAccessMode::Default,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        setup_with_config(config)
    }

    #[test]
    fn test_calc_real_path_with_rename_only() {
        let (fs, dir) = setup_with_rename_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let path1 = PathBuf::from("/prefix/x");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(dir.join("prefix").join("xy")));
    }

    #[test]
    fn test_calc_real_path_with_renamed_target_of_symlink() {
        let (fs, dir) = setup_with_rename_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/x", dir.join("y")).expect(err);

        let path1 = PathBuf::from("/y");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(dir.join("xy")));
    }

    #[test]
    fn test_calc_real_path_with_renamed_self_looping_symlink() {
        let (fs, dir) = setup_with_rename_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/x", dir.join("xy")).expect(err);

        let path1 = PathBuf::from("/xy");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();

        let path2 = PathBuf::from("/x");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();

        assert_eq!(ans1, PathAction::ELOOP);
        assert_eq!(ans2, PathAction::ELOOP);
    }

    #[test]
    fn test_calc_real_path_with_renamed_looping_symlinks() {
        let (fs, dir) = setup_with_rename_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/a", dir.join("xy")).expect(err);
        std::os::unix::fs::symlink("/x", dir.join("a")).expect(err);

        let path1 = PathBuf::from("/a");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();

        let path2 = PathBuf::from("/x");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();

        let path3 = PathBuf::from("/xy");
        let ans3 = fs.calc_real_path(path3.as_path(), syscall, &[]).unwrap();

        assert_eq!(ans1, PathAction::ELOOP);
        assert_eq!(ans2, PathAction::ELOOP);
        assert_eq!(ans3, PathAction::ELOOP);
    }

    #[test]
    fn test_calc_real_path_of_symlink_not_followed_with_rename() {
        let (fs, dir) = setup_with_rename_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_readlinkat as usize);
        let syscall = maybe_syscall.expect("SYS_readlinkat syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/x", dir.join("xy")).expect(err);

        let path1 = PathBuf::from("/xy");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();

        let path2 = PathBuf::from("/x");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();

        assert_eq!(ans1, PathAction::Override(dir.join("xy")));
        assert_eq!(ans2, PathAction::Override(dir.join("xy")));
    }

    fn setup_with_passthrough_config() -> (FileSystem, PathBuf) {
        let config = SysAugConfig {
            rootfs: RootfsConfig {
                passthroughs: vec![String::from("/prefix1")],
                ..Default::default()
            },
            ..Default::default()
        };
        setup_with_config(config)
    }

    #[test]
    fn test_calc_real_path_with_passthrough_path() {
        let (fs, dir) = setup_with_passthrough_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let path1 = PathBuf::from("/prefix1/file123.so");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();

        let path2 = PathBuf::from("/prefix123/file123.so");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();

        assert_eq!(ans1, PathAction::None);
        assert_eq!(
            ans2,
            PathAction::Override(dir.join("prefix123").join("file123.so"))
        );
    }

    #[test]
    fn test_calc_real_path_with_symlink_to_passthrough_path() {
        let (fs, dir) = setup_with_passthrough_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/prefix1/file123.so", dir.join("y")).expect(err);

        let path1 = PathBuf::from("/y");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override("/prefix1/file123.so".into()));
    }

    #[test]
    fn test_calc_real_path_with_symlink_to_passthrough_path_not_followed() {
        let (fs, dir) = setup_with_passthrough_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_readlinkat as usize);
        let syscall = maybe_syscall.expect("SYS_readlinkat syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/prefix1/file123.so", dir.join("y")).expect(err);

        let path1 = PathBuf::from("/y");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(dir.join("y")));
    }

    fn setup_with_cow_overlays_config() -> (FileSystem, PathBuf, PathBuf) {
        let err = "Failed to setup tests";
        let overlays_dir: PathBuf = PathBuf::from("../tests/fixtures/staging.overlays");
        let dir = overlays_dir.as_path();
        if dir.exists() {
            std::fs::remove_dir_all(dir).expect(err);
        }
        std::fs::create_dir_all(dir).expect(err);
        let overlays_dir = dir.canonicalize().expect(err);

        let overlay1 = overlays_dir.join("overlay1");
        let overlay2 = overlays_dir.join("overlay2");
        let overlay3 = overlays_dir.join("overlay3");

        std::fs::create_dir_all(&overlay1).expect(err);
        std::fs::create_dir_all(&overlay2).expect(err);
        std::fs::create_dir_all(&overlay3).expect(err);

        std::fs::write(overlay1.join("A"), "").expect(err);
        std::fs::write(overlay2.join("A"), "").expect(err);
        std::fs::write(overlay3.join("A"), "").expect(err);

        let config = SysAugConfig {
            mounts: vec![
                MountConfig {
                    source: overlay1.to_str().expect(err).into(),
                    target: String::from("/"),
                    fstype: String::from("overlay"),
                },
                MountConfig {
                    source: overlay2.to_str().expect(err).into(),
                    target: String::from("/mnt/abc"),
                    fstype: String::from("overlay"),
                },
                MountConfig {
                    source: overlay3.to_str().expect(err).into(),
                    target: String::from("/"),
                    fstype: String::from("overlay"),
                },
            ],
            ..Default::default()
        };
        let (fs, staging_dir) = setup_with_config(config);
        (fs, staging_dir, overlays_dir)
    }

    #[test]
    fn test_calc_real_path_readonly_with_cow_overlays() {
        let (fs, _, dir) = setup_with_cow_overlays_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let path1 = PathBuf::from("/A");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(dir.join("overlay3").join("A")));

        let path2 = PathBuf::from("/mnt/abc/A");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans2, PathAction::Override(dir.join("overlay2").join("A")));
    }

    fn setup_with_exclusion_config() -> (FileSystem, PathBuf) {
        let config = SysAugConfig {
            rootfs: RootfsConfig {
                rename_host_paths: vec![RenameConfig {
                    regex: Regex::new(r"^(.*)/x$").unwrap(),
                    replacement: None,
                    should_replace_all: false,
                    access_mode: RenameAccessMode::Default,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        setup_with_config(config)
    }

    #[test]
    fn test_calc_real_path_with_excluded_path() {
        let (fs, _) = setup_with_exclusion_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let path1 = PathBuf::from("/x");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::HidePath);
    }

    #[test]
    fn test_calc_real_path_with_excluded_target_of_symlink() {
        let (fs, dir) = setup_with_exclusion_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        let err = "Failed to setup tests";
        std::os::unix::fs::symlink("/x", dir.join("y")).expect(err);

        let path1 = PathBuf::from("/y");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::HidePath);
    }

    #[test]
    fn test_calc_guest_path_from_dirfd() {
        let (fs, dir) = setup();
        let ans = fs.calc_guest_path_from_dirfd(&None, &dir.join("/x"));
        assert_eq!(ans, Some("/x".into()));

        let ans = fs.calc_guest_path_from_dirfd(&None, &PathBuf::from("/abc/def"));
        assert_eq!(ans, Some("/abc/def".into()));

        let ans = fs.calc_guest_path_from_dirfd(&None, &PathBuf::from("relative/path"));
        assert_eq!(ans, None);

        let ans = fs.calc_guest_path_from_dirfd(&None, &PathBuf::from(""));
        assert_eq!(ans, Some("".into()));

        let ans = fs.calc_guest_path_from_dirfd(
            &Some(PathBuf::from("/abc")),
            &PathBuf::from("relative/path"),
        );
        assert_eq!(ans, Some("/abc/relative/path".into()));
    }
}
