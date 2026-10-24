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

use crate::common::{OverlayFileType, RootFsMetadata, SysAugError, display_err, get_metadata_dir};
use crate::fs::FileSystem;
use std::io::Seek;
use std::path::{Component, Path, PathBuf};
use tracing::{Level, event};

impl FileSystem {
    // -----------------------------------------------------------------------------
    // ------------------------ RootFS Metadata (Perms, etc) -----------------------
    // -----------------------------------------------------------------------------

    pub fn get_metadata_path(&self, path: &Path) -> Result<Option<PathBuf>, SysAugError> {
        let maybe_meta_path = Self::_resolve_metadata_path(self.consts.args.rootfs.as_ref(), path)?;
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
            // First, consider hardlink counter and CopyOnWrite mode
            let should_keep = self.save_metadata(path, |x| {
                if let Some(val) = x.hardlink_counter
                    && val > 1
                {
                    x.hardlink_counter = Some(val - 1);
                    return true;
                }
                if x.overlay_type.is_some() {
                    // any future write to this file should be considered CoW
                    x.overlay_type = Some(OverlayFileType::CoW);
                }
                x.overlay_type.is_some()
            })?;
            if should_keep == Some(true) {
                return Ok(());
            } else if let Ok(path) = path.canonicalize() {
                // First, delete the file backing the hardlink
                if !path.is_dir() {
                    let _ = std::fs::remove_file(path)
                        .map_err(SysAugError::DeleteMetadata)
                        .map_err(display_err);
                }
            }

            event!(
                Level::TRACE,
                "Deleting metadata file: {:?}",
                meta_path.to_string_lossy()
            );
            if !meta_path.exists() {
                return Ok(());
            }
            if !meta_path.is_dir() {
                let _ = std::fs::remove_file(meta_path)
                    .map_err(SysAugError::DeleteMetadata)
                    .map_err(display_err);
            }
        }

        if path.is_dir() {
            if let Some(mut meta_path) = self.get_metadata_path(path)? {
                meta_path.pop();
                let _ = std::fs::remove_dir_all(meta_path);
            }
        }
        Ok(())
    }

    /// This function does not check for hardlinks. But it does handle CopyOnWrite mode.
    pub fn rename_metadata(&self, path1: &Path, path2: &Path) -> Result<(), SysAugError> {
        if self.consts.args.rootfs.is_none() {
            return Ok(());
        }

        let Some(meta_path1) = self.get_metadata_path(path1)? else {
            return Ok(());
        };
        let Some(meta_path2) = self.get_metadata_path(path2)? else {
            return Ok(());
        };

        // First, create the parent folders for target if they don't exist
        let parent = meta_path2.parent().unwrap();
        std::fs::create_dir_all(parent).map_err(SysAugError::MetadataDir)?;

        let is_cow = self.save_metadata(path1, |x| {
            if x.overlay_type.is_some() {
                // Any write to path1 and path2 should be considered CoW
                x.overlay_type = Some(OverlayFileType::CoW);
            }
            x.overlay_type.is_some()
        })?;
        if is_cow == Some(true) {
            std::fs::copy(meta_path1, meta_path2).map_err(SysAugError::RenameMetadata)?;
            return Ok(());
        }
        let _ = std::fs::rename(meta_path1, meta_path2).map_err(SysAugError::RenameMetadata)?;
        Ok(())
    }

    /// Get the metadata path for a given path on host filesystem
    pub(crate) fn _resolve_metadata_path(
        rootfs: Option<&PathBuf>,
        path: &Path,
    ) -> Result<Option<PathBuf>, SysAugError> {
        let Some(mut metadir) = get_metadata_dir(rootfs) else {
            return Ok(None);
        };

        let maybe_canonical_path = if !path.exists() {
            if path.is_absolute() {
                std::path::absolute(path).ok()
            } else {
                None
            }
        } else {
            path.canonicalize().ok()
        };

        let Some(canonical_path) = maybe_canonical_path else {
            return Ok(None);
        };

        // Case 1: The file might be a hardlink, whose target is stored within the metadata dir
        if canonical_path.strip_prefix(&metadir).is_ok() {
            // Check whether this is a hardlink or a symlink to a hardlink
            let cloned_path = path.to_owned();
            let resolve_one_link = Self::_read_symlink(&cloned_path)?;
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

        // Case 2: The file must be stored in the rootfs directory
        metadir.push("rootfs");
        let Some(rootfs) = rootfs else {
            return Ok(None);
        };
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
}
