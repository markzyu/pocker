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

use crate::common::{SysAugError, SyscallInfo};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RenameConfig {
    #[serde(with = "serde_regex")]
    pub(crate) regex: Regex,

    /// If None, pocker will hide the file at this path.
    pub(crate) replacement: Option<String>,

    /// If false, replace only the earliest match.
    #[serde(default = "default_should_replace_all")]
    pub(crate) should_replace_all: bool,
}

fn default_should_replace_all() -> bool {
    false
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RootfsConfig {
    #[serde(default = "default_passthroughs")]
    pub(crate) passthroughs: Vec<String>,

    #[serde(default = "default_host_file_perms")]
    pub(crate) host_file_perms: usize,

    #[serde(default = "default_host_uid")]
    pub(crate) host_uid: usize,

    #[serde(default = "default_host_gid")]
    pub(crate) host_gid: usize,

    /// The key (original path) is a regex string with named captures. The value (new path) is a template string.
    #[serde(default = "default_rename_configs")]
    pub(crate) rename_guest_paths: Vec<RenameConfig>,

    #[serde(default = "default_rename_configs")]
    pub(crate) rename_host_paths: Vec<RenameConfig>,
}

fn default_passthroughs() -> Vec<String> {
    vec![
        // Linux systems
        "/dev".to_string(),
        "/proc".to_string(),
        "/sys".to_string(),
        // Android systems
        "/system/lib64".to_string(),
        "/system/lib".to_string(),
    ]
}

fn default_host_file_perms() -> usize {
    0o700
}

fn default_host_uid() -> usize {
    nix::unistd::getuid().as_raw() as usize
}

fn default_host_gid() -> usize {
    nix::unistd::getgid().as_raw() as usize
}

pub(crate) fn init_passthroughs_from_config(
    passthroughs: &mut Vec<PathBuf>,
    config: &RootfsConfig,
) {
    passthroughs.clear();
    for passthrough in &config.passthroughs {
        passthroughs.push(PathBuf::from(passthrough.clone()));
    }
}

fn default_rename_configs() -> Vec<RenameConfig> {
    vec![]
}

impl Default for RootfsConfig {
    fn default() -> Self {
        Self {
            passthroughs: default_passthroughs(),
            host_file_perms: default_host_file_perms(),
            host_uid: default_host_uid(),
            host_gid: default_host_gid(),
            rename_guest_paths: default_rename_configs(),
            rename_host_paths: default_rename_configs(),
        }
    }
}

pub(crate) const PERMS_IDBIT_UG: u8 = 4;
pub(crate) const PERMS_IDS_SIZE: usize = 8;

/**
* Check the res_bits of a system call and call the callback for each slot that is set.
* @param callback: The parameters are
 * The index of the register (regs.arg0-arg2) for which the bit is set.
 * A mutable ref of the actual ID value to read/write in AsyncHandler's `perms_ids`
*/
#[inline(always)]
pub(crate) fn walk_res_bits(
    syscall: &SyscallInfo,
    perms_ids: &RefCell<[Option<usize>; PERMS_IDS_SIZE]>,
    mut callback: impl FnMut(usize, &mut Option<usize>) -> Result<(), SysAugError>,
) -> Result<(), SysAugError> {
    let mut guard = perms_ids.borrow_mut();
    let ug_bit = syscall.res_bits & PERMS_IDBIT_UG;
    let res_bits = syscall.res_bits;
    for i in 0..2 {
        let mask = 1 << i;
        if res_bits & mask == 0 {
            continue;
        }

        let idx = ug_bit | (i as u8);
        callback(i, &mut guard[idx as usize])?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[repr(u8)]
pub(crate) enum ResfUgType {
    RealUid = 0,
    EffectiveUid = 1,
    SavedSetUid = 2,
    FileSystemUid = 3,
    RealGid = PERMS_IDBIT_UG | 0,
    EffectiveGid = PERMS_IDBIT_UG | 1,
    SavedSetGid = PERMS_IDBIT_UG | 2,
    FileSystemGid = PERMS_IDBIT_UG | 3,
}

impl ResfUgType {
    pub fn index(self) -> usize {
        self as u8 as usize
    }
}

impl FromStr for ResfUgType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "realUid" => Ok(ResfUgType::RealUid),
            "effectiveUid" => Ok(ResfUgType::EffectiveUid),
            "savedSetUid" => Ok(ResfUgType::SavedSetUid),
            "fileSystemUid" => Ok(ResfUgType::FileSystemUid),
            "realGid" => Ok(ResfUgType::RealGid),
            "effectiveGid" => Ok(ResfUgType::EffectiveGid),
            "savedSetGid" => Ok(ResfUgType::SavedSetGid),
            "fileSystemGid" => Ok(ResfUgType::FileSystemGid),
            _ => Err(format!("Invalid ResfUgType: {}", s)),
        }
    }
}

pub(crate) fn init_perms_ids_from_config(
    perms_ids: &RefCell<[Option<usize>; PERMS_IDS_SIZE]>,
    config: &PermsConfig,
) -> Result<(), SysAugError> {
    let mut guard = perms_ids.borrow_mut();
    for (ty, id) in &config.root_ids {
        guard[ty.index()] = Some(*id);
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermsConfig {
    #[serde(default = "default_root_ids")]
    pub(crate) root_ids: HashMap<ResfUgType, usize>,
}

fn default_root_ids() -> HashMap<ResfUgType, usize> {
    let mut map = HashMap::new();
    map.insert(ResfUgType::RealUid, 0);
    map.insert(ResfUgType::EffectiveUid, 0);
    map.insert(ResfUgType::SavedSetUid, 0);
    map.insert(ResfUgType::FileSystemUid, 0);
    map.insert(ResfUgType::RealGid, 0);
    map.insert(ResfUgType::EffectiveGid, 0);
    map.insert(ResfUgType::SavedSetGid, 0);
    map.insert(ResfUgType::FileSystemGid, 0);
    map
}

impl Default for PermsConfig {
    fn default() -> Self {
        Self {
            root_ids: default_root_ids(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SysAugConfig {
    #[serde(default)]
    pub(crate) rootfs: RootfsConfig,
    #[serde(default)]
    pub(crate) perms: PermsConfig,
}

impl Default for SysAugConfig {
    fn default() -> Self {
        Self {
            rootfs: RootfsConfig::default(),
            perms: PermsConfig::default(),
        }
    }
}
