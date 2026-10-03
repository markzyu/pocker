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

mod aug_clone;
mod aug_common;
mod aug_exec;
mod aug_paths_common;
mod aug_paths_getdents;
mod aug_paths_links;
mod aug_paths_stat;
mod aug_paths;
mod aug_perms;
mod aug_seccomp;
mod aug_waitpid;
mod common;
mod config;
mod handler_async;
mod handler_sync;
mod syscalls;

pub use crate::common::{
    DelType, PermType, PermsMode, SysAugArgs, SysAugError, SyscallInfo, display_err, rwlock_read,
    rwlock_replace, rwlock_write, rwoption_replace, rwoption_setdefault, rwoption_take,
};
pub use crate::handler_sync::{TraceeHandler, TraceeHandlerConsts};
pub use crate::syscalls::{RAW_SYSCALL_INFOS, SYSCALL_INFOS};
