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

use crate::common::ProcfsError;
use std::io::ErrorKind;
use std::path::PathBuf;

pub fn getcwd(pid: nix::unistd::Pid) -> Result<PathBuf, ProcfsError> {
    let mut path = pid_path(pid);
    path.push("cwd");
    path.read_link().map_err(ProcfsError::IO)
}

pub fn getfd_path(pid: nix::unistd::Pid, fd: isize) -> Result<Option<PathBuf>, ProcfsError> {
    let mut path = pid_path(pid);
    path.push("fd");
    path.push(fd.to_string());
    match path.read_link() {
        Ok(ans) if ans.is_absolute() => Ok(Some(ans)),
        Ok(_) => Ok(None),
        Err(ref e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ProcfsError::IO(e)),
    }
}

fn pid_path(pid: nix::unistd::Pid) -> PathBuf {
    let mut path = PathBuf::new();
    path.push("/proc");
    path.push(pid.as_raw().to_string());
    path
}
