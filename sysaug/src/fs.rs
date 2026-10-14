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
use crate::config::{RenameConfig, init_passthroughs_from_config, init_rename_rules_from_config};
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

        Ok(Self {
            consts,
            path_prefix: RefCell::new(path_prefix),
            path_prefix_excludes: RefCell::new(path_prefix_excludes),
            rename_host_paths: RefCell::new(rename_host_paths),
            rename_guest_paths: RefCell::new(rename_guest_paths),
            pid: pid,
        })
    }

    pub(crate) fn _read_symlink(&self, path: &PathBuf) -> Result<Option<PathBuf>, SysAugError> {
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
