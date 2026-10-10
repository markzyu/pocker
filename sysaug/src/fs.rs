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

use crate::TraceeHandlerConsts;
use crate::common::{PathAction, RootFsMetadata, SysAugError, SyscallInfo, display_err};
use crate::config::init_passthroughs_from_config;
use nix::unistd::Pid;
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::OsString;
use std::io::Seek;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};
use tracing::{Level, event};

pub struct FileSystem {
    consts: TraceeHandlerConsts,
    pub path_prefix: RefCell<Option<PathBuf>>,
    pub path_prefix_excludes: RefCell<Vec<PathBuf>>,
    pid: Pid,
}

// Common helper functions used by aug_*.rs
// Calculate real path of file based on its path in rootfs
impl FileSystem {
    pub fn new(consts: TraceeHandlerConsts, pid: Pid) -> Self {
        let mut path_prefix: Option<PathBuf> = None;
        let mut path_prefix_excludes: Vec<PathBuf> = Vec::new();

        // Derive internal states from RootfsConfig.passthroughs and SysAugArgs.chroot
        if consts.args.chroot.is_some() {
            init_passthroughs_from_config(&mut path_prefix_excludes, &consts.config.rootfs);
            path_prefix = consts.args.chroot.clone();
        }

        Self {
            consts,
            path_prefix: RefCell::new(path_prefix),
            path_prefix_excludes: RefCell::new(path_prefix_excludes),
            pid: pid,
        }
    }

    // -----------------------------------------------------------------------------
    // ------------------------ RootFS Metadata (Perms, etc) -----------------------
    // -----------------------------------------------------------------------------

    pub fn get_metadata_path(&self, path: &Path) -> Result<Option<PathBuf>, SysAugError> {
        if self.consts.args.rootfs.is_none() {
            return Ok(None);
        }
        let maybe_meta_path = self.__resolve_metadata_path(path)?;
        event!(
            Level::TRACE,
            "Checking metadata for: {:?} = {:?}",
            path.to_string_lossy(),
            maybe_meta_path,
        );
        Ok(maybe_meta_path)
    }

    pub fn save_metadata<T>(
        &self,
        path: &Path,
        update_fn: impl FnOnce(&mut RootFsMetadata) -> T,
    ) -> Result<Option<T>, SysAugError> {
        if self.consts.args.rootfs.is_none() {
            return Ok(None);
        }
        let mut result: Option<T> = None;
        if let Some(meta_path) = self.get_metadata_path(path)? {
            event!(
                Level::INFO,
                "Writing metadata file: {:?}",
                meta_path.to_string_lossy()
            );
            let exists = std::fs::exists(&meta_path).map_err(SysAugError::CheckRootFsMetadata)?;
            let metadir = meta_path.parent().unwrap();
            let _ = std::fs::create_dir_all(metadir)
                .map_err(SysAugError::MetadataDir)
                .map_err(display_err);
            let file = std::fs::File::options()
                .write(true)
                .read(true)
                .create(true)
                .open(&meta_path)
                .map_err(|e| SysAugError::WriteMetadata(e.to_string()))?;
            let mut file = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
                .map_err(|_| SysAugError::LockRootFsMetadata)?;

            let mut curr_data: RootFsMetadata = if !exists {
                RootFsMetadata::default()
            } else {
                serde_json::from_reader(&*file).map_err(SysAugError::ParseRootFsMetadata)?
            };

            result.replace(update_fn(&mut curr_data));

            if exists {
                file.seek(std::io::SeekFrom::Start(0))
                    .map_err(SysAugError::WriteRootFsMetadata)?;
                file.set_len(0).map_err(SysAugError::WriteRootFsMetadata)?;
            }
            serde_json::to_writer(&*file, &curr_data).map_err(SysAugError::WriteRootFsMetadata2)?;
        }
        Ok(result)
    }

    pub fn read_metadata(&self, path: &Path) -> Result<Option<RootFsMetadata>, SysAugError> {
        if self.consts.args.rootfs.is_none() {
            return Ok(None);
        }
        if let Some(meta_path) = self.get_metadata_path(path)? {
            event!(
                Level::DEBUG,
                "Reading metadata file: {:?}",
                meta_path.to_string_lossy()
            );
            if !std::fs::exists(&meta_path).map_err(SysAugError::CheckRootFsMetadata)? {
                return Ok(None);
            }
            let file = std::fs::File::options()
                .read(true)
                .open(meta_path)
                .map_err(|e| SysAugError::WriteMetadata(e.to_string()))?;
            return Ok(serde_json::from_reader(file).map_err(SysAugError::ParseRootFsMetadata)?);
        }
        Ok(None)
    }

    pub fn delete_metadata(&self, path: &Path) -> Result<(), SysAugError> {
        if self.consts.args.rootfs.is_none() {
            return Ok(());
        }
        if let Some(meta_path) = self.get_metadata_path(path)? {
            // First, consider hardlink counter
            let should_keep = self.save_metadata(path, |x| {
                if let Some(val) = x.hardlink_counter
                    && val > 1
                {
                    x.hardlink_counter = Some(val - 1);
                    return true;
                }
                false
            })?;
            if should_keep == Some(true) {
                return Ok(());
            } else if let Ok(path) = path.canonicalize() {
                // First, delete the file backing the hardlink
                let _ = std::fs::remove_file(path)
                    .map_err(SysAugError::DeleteMetadata)
                    .map_err(display_err);
            }

            event!(
                Level::TRACE,
                "Deleting metadata file: {:?}",
                meta_path.to_string_lossy()
            );
            if !meta_path.exists() {
                return Ok(());
            }
            let _ = std::fs::remove_file(meta_path)
                .map_err(SysAugError::DeleteMetadata)
                .map_err(display_err);
        }

        if path.is_dir() {
            if let Some(mut meta_path) = self.get_metadata_path(path)? {
                meta_path.pop();
                let _ = std::fs::remove_dir_all(meta_path);
            }
        }
        Ok(())
    }

    pub fn get_metadata_dir(&self) -> Option<PathBuf> {
        let args = &self.consts.args;
        let Some(rootfs) = args.rootfs.as_ref() else {
            return None;
        };
        if rootfs == Path::new("/") {
            // If setting real root as chroot/rootfs, don't create metadata
            return None;
        }

        // This unwrap() works on the assumption that args.rootfs is a canonicalized path
        let mut metaname = rootfs.file_name().unwrap().to_os_string();
        metaname.push(".metadata");
        let metadir = rootfs.with_file_name(metaname);
        Some(metadir)
    }

    fn __resolve_metadata_path(&self, path: &Path) -> Result<Option<PathBuf>, SysAugError> {
        let Some(mut metadir) = self.get_metadata_dir() else {
            return Ok(None);
        };

        if !path.exists() {
            return Ok(None);
        }

        // Note: canonicalize() will also resolve ALL symlinks
        let Ok(canonical_path) = path.canonicalize() else {
            return Ok(None);
        };

        // Case 1: The file might be a hardlink, whose target is stored within the metadata dir
        if canonical_path.strip_prefix(&metadir).is_ok() {
            // Check whether this is a hardlink or a symlink to a hardlink
            let cloned_path = path.to_owned();
            let resolve_one_link = self._read_symlink(&cloned_path)?;
            let is_simple_hardlink = resolve_one_link.as_ref() == Some(&canonical_path)
                || &cloned_path == &canonical_path;
            if is_simple_hardlink {
                let Some(basename) = canonical_path.file_name() else {
                    return Ok(None);
                };

                let mut basename = basename.to_os_string();
                basename.push(".json");
                return Ok(Some(canonical_path.with_file_name(&basename)));
            } else {
                event!(
                    Level::DEBUG,
                    "Hardlink corner case, file {:?}, backing {:?}",
                    path,
                    &canonical_path
                );
            }
        }

        // Case 2: The file is stored in the rootfs dir
        metadir.push("rootfs");
        let rootfs = self.consts.args.rootfs.as_ref().unwrap();
        let Ok(relative_path) = canonical_path.strip_prefix(rootfs) else {
            return Ok(None);
        };

        metadir.push("chld");
        for component in relative_path.components() {
            if component == Component::CurDir {
                continue;
            }
            if component == Component::RootDir {
                continue;
            }
            if let Component::Normal(part) = component {
                metadir.push(part);
                metadir.push("chld");
            } else {
                return Ok(None);
            }
        }
        metadir.pop();
        Ok(Some(metadir.join("meta")))
    }

    // -----------------------------------------------------------------------------
    // ------------------------ Path Modifications (Chroot) ------------------------
    // -----------------------------------------------------------------------------

    pub fn calc_real_path(
        &self,
        orig_path: &Path,
        syscall: &SyscallInfo,
        args: &[usize],
    ) -> Result<PathAction, SysAugError> {
        let result = self.calc_real_path_recurse(orig_path, syscall, HashSet::new(), args)?;
        event!(
            Level::DEBUG,
            "Following symlink {:?} -> {:?}",
            orig_path,
            &result
        );
        Ok(result)
    }

    fn calc_real_path_simple(
        &self,
        orig_path: &Path,
        syscall: &SyscallInfo,
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

        self.get_mod_path(syscall, orig_path, new_path, false)
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
        let action = self.calc_real_path_simple(orig_path, syscall)?;
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

    fn _read_symlink(&self, path: &PathBuf) -> Result<Option<PathBuf>, SysAugError> {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if !metadata.file_type().is_symlink() {
                return Ok(None);
            }
            let link = path.read_link().map_err(SysAugError::ReadSymlink)?;
            if link.is_relative() {
                return Ok(None);
            }
            return Ok(Some(link));
        }
        Ok(None)
    }

    // There are SysAugConfig configurations that can "modify" a guest/host path. This function applies them.
    // reverse: false = generating real paths on disk, true = generating fake paths from container
    // perspective
    pub fn get_mod_path(
        &self,
        _syscall: &SyscallInfo,
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
            &self.consts.config.rootfs.rename_guest_paths
        } else {
            &self.consts.config.rootfs.rename_host_paths
        };
        for config in rename_map {
            if config.regex.is_match(bytes_str) {
                let Some(ref replacement) = config.replacement else {
                    return Ok(PathAction::HidePath);
                };
                let replacement_bytes = replacement.as_bytes();
                let replacement = if config.should_replace_all {
                    config.regex.replace_all(bytes_str, replacement_bytes)
                } else {
                    config.regex.replace(bytes_str, replacement_bytes)
                };
                let os_str = OsString::from_vec(replacement.into());
                return Ok(PathAction::Override(os_str.into()));
            }
        }
        Ok(initial_override)
    }

    /// Consider dirfd (which is a host path) and return the guest path, or None if not found.
    ///
    /// For this to work properly,
    ///
    /// * The `dirfd_path` should be the current workdir if syscall has no dirfd.
    /// * The `dirfd_path` should be the current workdir if dirfd is AT_FDCWD.
    /// * The `dirfd_path` should be Some("/absolute/path") for files.
    /// * The `dirfd_path` should be None for pipes and other non-file FDs.
    pub fn calc_guest_path_from_dirfd(
        &self,
        dirfd_path: &Option<PathBuf>,
        orig_path: &PathBuf,
    ) -> Result<Option<PathBuf>, SysAugError> {
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
            return Ok(Some(orig_path));
        }

        // If the path is not absolute, then inform downstream of ENOENT
        if orig_path.is_relative() {
            return Ok(None);
        }
        let Ok(orig_path) = std::path::absolute(&orig_path) else {
            return Ok(None);
        };

        // Strip the prefix if it matches
        let path_prefix = {
            let default = PathBuf::from("/");
            let guard = self.path_prefix.borrow();
            guard.as_ref().unwrap_or(&default).clone()
        };
        if let Ok(stripped) = orig_path.strip_prefix(path_prefix) {
            let root = PathBuf::from("/");
            return Ok(Some(root.join(stripped)));
        }

        // Otherwise, return the path as is
        // (It could match a rename rule or an exclusion rule)
        Ok(Some(orig_path))
    }
}

pub fn path_from_bytes(mut path_bytes: Vec<u8>) -> Result<PathBuf, SysAugError> {
    while path_bytes.last() == Some(&0) {
        path_bytes.pop();
    }
    let path_osstr: OsString = OsStringExt::from_vec(path_bytes);
    Ok(path_osstr.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::get_syscall;
    use crate::{SysAugArgs, config::*};
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

        let err = "Failed to setup tests";
        let staging_absolute = dir.canonicalize().expect(err);
        let consts = TraceeHandlerConsts {
            config,
            args: SysAugArgs {
                chroot: Some(staging_absolute.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let fs = FileSystem::new(consts, Pid::this());
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

    fn setup_with_rename_config() -> (FileSystem, PathBuf) {
        let config = SysAugConfig {
            rootfs: RootfsConfig {
                rename_host_paths: vec![RenameConfig {
                    regex: Regex::new(r"^(.*)/x$").unwrap(),
                    replacement: Some(String::from("$1/xy")),
                    should_replace_all: false,
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

    fn setup_with_exclusion_config() -> (FileSystem, PathBuf) {
        let config = SysAugConfig {
            rootfs: RootfsConfig {
                rename_host_paths: vec![RenameConfig {
                    regex: Regex::new(r"^(.*)/x$").unwrap(),
                    replacement: None,
                    should_replace_all: false,
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
}
