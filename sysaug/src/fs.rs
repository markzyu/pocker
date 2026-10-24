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
use crate::common::SysAugError;
use crate::config::{
    MetadataLayerConfig, RenameConfig, init_metadata_layers_from_config,
    init_passthroughs_from_config, init_rename_rules_from_config,
};
use nix::unistd::Pid;
use std::cell::RefCell;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

/// Common File System helper functions used by aug_*.rs
/// * calculates real path of file based on its path in rootfs
/// * provides access to metadata for rootfs files and directories
pub struct FileSystem {
    pub consts: TraceeHandlerConsts,
    /// The editable prefix, in case factors other than configs are involved
    pub path_prefix: RefCell<Option<PathBuf>>,
    /// The editable exclude list, in case factors other than configs are involved
    pub path_prefix_excludes: RefCell<Vec<PathBuf>>,
    /// The editable host rename rules, in case factors other than configs are involved
    pub rename_host_paths: RefCell<Vec<RenameConfig>>,
    /// The editable guest rename rules, in case factors other than configs are involved
    pub rename_guest_paths: RefCell<Vec<RenameConfig>>,
    /// The editable getdents layers, in case factors other than configs are involved
    pub metadata_layers: RefCell<Vec<MetadataLayerConfig>>,
    pub pid: Pid,
}

impl FileSystem {
    pub fn new(consts: TraceeHandlerConsts, pid: Pid) -> Result<Self, SysAugError> {
        let mut path_prefix: Option<PathBuf> = None;
        let mut path_prefix_excludes: Vec<PathBuf> = Vec::new();

        // Derive internal states from RootfsConfig.passthroughs and SysAugArgs.chroot
        if consts.args.chroot.is_some() {
            init_passthroughs_from_config(&mut path_prefix_excludes, &consts.config.rootfs);
            path_prefix = consts.args.chroot.clone();
        }

        let mut rename_host_paths: Vec<RenameConfig> = Vec::new();
        let mut rename_guest_paths: Vec<RenameConfig> = Vec::new();
        init_rename_rules_from_config(
            &mut rename_host_paths,
            &mut rename_guest_paths,
            &consts.config,
            match path_prefix.as_ref() {
                Some(path) => path.clone(),
                None => PathBuf::from("/"),
            },
        )?;

        let mut metadata_layers: Vec<MetadataLayerConfig> = Vec::new();
        init_metadata_layers_from_config(&mut metadata_layers, &consts.config, &consts.args.chroot);

        Ok(Self {
            consts,
            path_prefix: RefCell::new(path_prefix),
            path_prefix_excludes: RefCell::new(path_prefix_excludes),
            rename_host_paths: RefCell::new(rename_host_paths),
            rename_guest_paths: RefCell::new(rename_guest_paths),
            metadata_layers: RefCell::new(metadata_layers),
            pid: pid,
        })
    }

    pub(crate) fn _read_symlink(path: &PathBuf) -> Result<Option<PathBuf>, SysAugError> {
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
}

pub fn path_from_bytes(mut path_bytes: Vec<u8>) -> Result<PathBuf, SysAugError> {
    while path_bytes.last() == Some(&0) {
        path_bytes.pop();
    }
    let path_osstr: OsString = OsStringExt::from_vec(path_bytes);
    Ok(path_osstr.into())
}

#[cfg(test)]
#[serial_test::serial]
mod tests {
    use super::*;
    use crate::common::PathAction;
    use crate::config::*;
    use crate::syscalls::get_syscall;
    use crate::{SysAugArgs, TraceeHandlerConsts};
    use nix::unistd::Pid;
    use regex::bytes::Regex;

    // returns (fs, absolute path of staging dir / of rootfs)
    fn setup_with_config(config: SysAugConfig) -> (FileSystem, PathBuf) {
        let err = "Failed to setup tests";
        let staging_dir: PathBuf = PathBuf::from("../tests/fixtures/staging");
        let meta_dir: PathBuf = PathBuf::from("../tests/fixtures/staging.metadata");
        let dir = staging_dir.as_path();
        if dir.exists() {
            std::fs::remove_dir_all(dir).expect(err);
        }
        if meta_dir.exists() {
            std::fs::remove_dir_all(&meta_dir).expect(err);
        }
        std::fs::create_dir_all(dir).expect(err);
        std::fs::write(dir.join("x"), "123").expect(err);
        let staging_absolute = dir.canonicalize().expect(err);

        let consts = TraceeHandlerConsts {
            config,
            args: SysAugArgs {
                chroot: Some(staging_absolute.clone()),
                rootfs: Some(staging_absolute.clone()),
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

        std::fs::write(overlay1.join("A"), "9").expect(err);
        std::fs::write(overlay2.join("A"), "8").expect(err);
        std::fs::write(overlay3.join("A"), "7").expect(err);

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
        let expect_path1 = dir.join("overlay3").join("A");
        assert_eq!(ans1, PathAction::Override(expect_path1.clone()));

        let path2 = PathBuf::from("/mnt/abc/A");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();
        let expect_path2 = dir.join("overlay2").join("A");
        assert_eq!(ans2, PathAction::Override(expect_path2.clone()));

        // We haven't copied the file to rootfs so there is no metadata
        assert!(fs.read_metadata(expect_path1.as_path()).unwrap().is_none());
        assert!(fs.read_metadata(expect_path2.as_path()).unwrap().is_none());
    }

    #[test]
    fn test_calc_real_path_writes_with_cow_overlays() {
        let (fs, dir, _) = setup_with_cow_overlays_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_mkdir as usize);
        let syscall = maybe_syscall.expect("SYS_mkdir syscall info");

        let path1 = PathBuf::from("/A");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        let expect_path1 = dir.join("A");
        assert_eq!(ans1, PathAction::Override(expect_path1.clone()));
        assert_eq!(
            std::fs::read_to_string(&expect_path1).unwrap(),
            "7".to_string()
        );

        std::fs::create_dir_all(dir.join("mnt/abc")).expect("test setup");

        let path2 = PathBuf::from("/mnt/abc/A");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();
        let expect_path2 = dir.join("mnt/abc/A");
        assert_eq!(ans2, PathAction::Override(expect_path2.clone()));
        assert_eq!(
            std::fs::read_to_string(&expect_path2).unwrap(),
            "8".to_string()
        );

        // Check that metadata exists
        assert!(fs.read_metadata(expect_path1.as_path()).unwrap().is_some());
        assert!(fs.read_metadata(expect_path2.as_path()).unwrap().is_some());
    }

    #[test]
    fn test_calc_real_path_read_after_write_with_cow_overlays() {
        let (fs, dir, _) = setup_with_cow_overlays_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");

        std::fs::write(dir.join("A"), "10").expect("test setup");
        std::fs::create_dir_all(dir.join("mnt/abc")).expect("test setup");
        std::fs::write(dir.join("mnt/abc/A"), "10").expect("test setup");

        let path1 = PathBuf::from("/A");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(dir.join("A")));

        let path2 = PathBuf::from("/mnt/abc/A");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans2, PathAction::Override(dir.join("mnt/abc/A")));
    }

    #[test]
    fn test_calc_real_path_cow_whiteout_file() {
        let (fs, dir, _) = setup_with_cow_overlays_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_mkdir as usize);
        let syscall = maybe_syscall.expect("SYS_mkdir syscall info");
        std::fs::create_dir_all(dir.join("mnt/abc")).expect("test setup");

        // First, create cow copies
        let path1 = PathBuf::from("/A");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        let expect_path1 = dir.join("A");
        assert_eq!(ans1, PathAction::Override(expect_path1.clone()));

        let path2 = PathBuf::from("/mnt/abc/A");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();
        let expect_path2 = dir.join("mnt/abc/A");
        assert_eq!(ans2, PathAction::Override(expect_path2.clone()));

        // Then, delete the copies
        fs.delete_metadata(expect_path1.as_path())
            .expect("setting up whiteout");
        fs.delete_metadata(expect_path2.as_path())
            .expect("setting up whiteout");
        std::fs::remove_file(&expect_path1).expect("setting up whiteout");
        std::fs::remove_file(&expect_path2).expect("setting up whiteout");

        assert!(fs.read_metadata(expect_path1.as_path()).unwrap().is_some());
        assert!(fs.read_metadata(expect_path2.as_path()).unwrap().is_some());

        // Now, access to the deleted files should use the latest layer (ENOENT)
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");
        let path1 = PathBuf::from("/A");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(dir.join("A")));

        let path2 = PathBuf::from("/mnt/abc/A");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans2, PathAction::Override(dir.join("mnt/abc/A")));
    }

    #[test]
    fn test_calc_real_path_cow_rename_files() {
        let (fs, dir, dir2) = setup_with_cow_overlays_config();
        let (maybe_syscall, _) = get_syscall(libc::SYS_mkdir as usize);
        let syscall = maybe_syscall.expect("SYS_mkdir syscall info");
        std::fs::create_dir_all(dir.join("mnt/abc")).expect("test setup");

        // First, create cow copies
        let path1 = PathBuf::from("/A");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        let expect_path1 = dir.join("A");
        assert_eq!(ans1, PathAction::Override(expect_path1.clone()));

        let path2 = PathBuf::from("/mnt/abc/A");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();
        let expect_path2 = dir.join("mnt/abc/A");
        assert_eq!(ans2, PathAction::Override(expect_path2.clone()));

        // Then, rename the copies
        let new_path1 = dir.join("B");
        let new_path2 = dir.join("mnt/abc/B");
        std::fs::rename(&expect_path1, new_path1.as_path()).expect("rename");
        std::fs::rename(&expect_path2, new_path2.as_path()).expect("rename");
        fs.rename_metadata(expect_path1.as_path(), new_path1.as_path())
            .expect("rename");
        fs.rename_metadata(expect_path2.as_path(), new_path2.as_path())
            .expect("rename");

        assert!(fs.read_metadata(new_path1.as_path()).unwrap().is_some());
        assert!(fs.read_metadata(new_path2.as_path()).unwrap().is_some());
        assert!(fs.read_metadata(expect_path1.as_path()).unwrap().is_some());
        assert!(fs.read_metadata(expect_path2.as_path()).unwrap().is_some());

        let invalid_copy1 = dir2.join("overlay3").join("B");
        let invalid_copy2 = dir2.join("overlay2").join("B");
        assert!(!expect_path1.exists());
        assert!(!expect_path2.exists());
        assert!(!invalid_copy1.exists());
        assert!(!invalid_copy2.exists());
        assert!(new_path1.exists());
        assert!(new_path2.exists());

        // Now try to access the files that "no longer exist"
        let (maybe_syscall, _) = get_syscall(libc::SYS_chdir as usize);
        let syscall = maybe_syscall.expect("SYS_chdir syscall info");
        let path1 = PathBuf::from("/A");
        let ans1 = fs.calc_real_path(path1.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans1, PathAction::Override(dir.join("A")));

        let path2 = PathBuf::from("/mnt/abc/A");
        let ans2 = fs.calc_real_path(path2.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans2, PathAction::Override(dir.join("mnt/abc/A")));

        // Now try to access the files that were renamed
        let path3 = PathBuf::from("/B");
        let ans3 = fs.calc_real_path(path3.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans3, PathAction::Override(dir.join("B")));

        let path4 = PathBuf::from("/mnt/abc/B");
        let ans4 = fs.calc_real_path(path4.as_path(), syscall, &[]).unwrap();
        assert_eq!(ans4, PathAction::Override(dir.join("mnt/abc/B")));
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
