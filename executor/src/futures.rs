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
use nix::sys::wait::WaitStatus;

// TODO: Move this to sysaug crate (keep async runtime stuff in krsm only)

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum PtraceFutureTypes {
    WaitForPtraceSeccomp,
    /// Warning: This can happen at both syscall-exit-stop and syscall-entry-stop
    WaitForPtraceSyscall,
    WaitForPtraceEvent,
    WaitForSignal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtraceStatus {
    pub wait_status: WaitStatus,
}

pub type PtraceAsyncRuntime = krsm::AsyncRuntime<PtraceFutureTypes, PtraceStatus, 4>;
