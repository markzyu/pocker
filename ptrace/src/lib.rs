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

mod common;
mod mem_direct;
mod mem_slow;

pub use crate::common::{
    CHeader, CStruct, GenericPurposeRegs, MAX_NUM_TRACEES, MemHelpers, NixISize,
    PTRACE_GETEVENTMSG, PtraceError, SHARED_MMAP_SIZE, SHARED_REGIONS, STACK_SAFE_ZONE_SIZE,
    SharedRegionContent, USIZE_SIZE, getregs, read_bytes_to_fixed_sized_objs,
    read_bytes_to_structs, setregs, write, write_fixed_sized_objs_to_tracee,
    write_structs_to_tracee,
};
pub use crate::mem_direct::{DIRECT_MEM_HELPERS, get_own_region_id, set_tracee_write_region_addr};
pub use crate::mem_slow::SLOW_MEM_HELPERS;

use nix::sys;
use nix::sys::memfd;
use nix::sys::mman;
use nix::sys::wait;
use nix::unistd;
use std::convert::TryInto;
use std::os::fd::AsRawFd;
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process;
use tracing::{Level, event};

pub fn is_trace_stop(status: &wait::WaitStatus) -> bool {
    matches!(
        status,
        wait::WaitStatus::PtraceEvent(_, _, _)
            | wait::WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP)
    )
}

pub fn is_syscall_stop(status: &wait::WaitStatus) -> bool {
    matches!(status, wait::WaitStatus::PtraceSyscall(_))
}

pub fn is_still_alive(status: &wait::WaitStatus) -> bool {
    !matches!(status, wait::WaitStatus::Exited(_, _))
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct PtraceSyscallInfo {
    pub op: u8,
    _reserved1: u8,
    flags: u16,
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    _reserved2: [u64; 3],
}

/// Assumption: This assumes the entire tracer program calls `start` only once
///             So that it can safely initialize global, shared, mmap regions
pub fn start(
    cmd: &mut process::Command,
    no_attach: bool,
) -> Result<(unistd::Pid, RawFd, usize), PtraceError> {
    // Note: All FDs will auto close when dropped.

    // Open many empty FDs to at least make sure we get a high number as FD,
    //   so that we don't clobber FD3 (commonly used in bash scripts)
    let shared_fd = {
        let _empty_fds = (0..27)
            .map(|_| {
                memfd::memfd_create("empty", memfd::MFdFlags::empty())
                    .map_err(PtraceError::CreateMemoryFile)
            })
            .collect::<Result<Vec<OwnedFd>, _>>()?;

        memfd::memfd_create("shared_from_tracer", memfd::MFdFlags::empty())
            .map_err(PtraceError::CreateMemoryFile)?
    };

    // Continue to setup the shared_fd to have the correct mmap size
    unistd::ftruncate(&shared_fd, SHARED_MMAP_SIZE as NixISize)
        .map_err(PtraceError::CreateMemoryFile)?;
    let mmap_addr = unsafe {
        mman::mmap(
            None,
            SHARED_MMAP_SIZE.try_into().unwrap(),
            mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
            mman::MapFlags::MAP_SHARED,
            &shared_fd,
            0,
        )
        .map_err(PtraceError::CreateMemoryFile)?
        .as_ptr() as usize
    };

    unsafe {
        for i in 0..MAX_NUM_TRACEES {
            let start_tracee = (mmap_addr + i * STACK_SAFE_ZONE_SIZE) as *mut SharedRegionContent;
            let mut region_box = SHARED_REGIONS[i]
                .write()
                .map_err(|_| PtraceError::LockGlobalMmap)?;
            *region_box = Some(Box::from_raw(start_tracee));
        }
    }

    event!(
        Level::INFO,
        "Created shared mmap fd {:?} addr {:x}",
        shared_fd,
        mmap_addr
    );
    match unsafe { unistd::fork() } {
        Ok(unistd::ForkResult::Parent { child, .. }) => {
            Ok((child, shared_fd.as_raw_fd(), mmap_addr))
        }
        Ok(unistd::ForkResult::Child) => {
            if no_attach {
                // Use PTRACE_TRACEME, and wait for tracer's main thread
                nix::sys::ptrace::traceme().unwrap();
            } else {
                // Pause child execution and wait for tracer to PTRACE_ATTACH
                sys::signal::raise(sys::signal::Signal::SIGSTOP).unwrap();
            }
            let e = cmd.exec();
            println!("[ERROR] Unexpected exec failure, returned {:?}", &e);
            Err(PtraceError::InitCmdFailed(e))
        }
        Err(e) => Err(PtraceError::StartInitCmd(e)),
    }
}

pub fn pid(child: &process::Child) -> Result<nix::unistd::Pid, PtraceError> {
    let raw_id: u64 = child.id().into();
    let pid: libc::pid_t = raw_id
        .try_into()
        .map_err(|e| PtraceError::ParsePid(raw_id, e))?;
    Ok(nix::unistd::Pid::from_raw(pid))
}

pub fn waitpid(pid: nix::unistd::Pid) -> Result<wait::WaitStatus, PtraceError> {
    wait::waitpid(pid, Some(wait::WaitPidFlag::WNOHANG)).map_err(PtraceError::Waitpid)
}

pub fn wait(child: &process::Child) -> Result<wait::WaitStatus, PtraceError> {
    waitpid(pid(child)?)
}

pub fn waitpid_hang(pid: nix::unistd::Pid) -> Result<wait::WaitStatus, PtraceError> {
    wait::waitpid(pid, None).map_err(PtraceError::Waitpid)
}

pub fn wait_hang(child: &process::Child) -> Result<wait::WaitStatus, PtraceError> {
    waitpid_hang(pid(child)?)
}

pub fn getevent(pid: nix::unistd::Pid) -> Result<libc::c_ulong, PtraceError> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(
            PTRACE_GETEVENTMSG,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<libc::c_void>(),
            data.as_mut_ptr() as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::GetEventMsg)?;
    Ok(unsafe { data.assume_init() })
}

#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
pub fn set_syscall_num(pid: nix::unistd::Pid, val: usize) -> Result<(), PtraceError> {
    let mut regs = getregs(pid)?;
    event!(
        Level::DEBUG,
        "Replacing syscall {} with {}",
        regs.syscall_num,
        val,
    );

    regs.syscall_num = val;
    setregs(pid, regs)?;

    let regs2 = getregs(pid)?;
    event!(
        Level::TRACE,
        "Confirm regs: syscall {} with {:x} {:x} {:x}",
        regs2.syscall_num,
        regs2.arg0,
        regs2.arg1,
        regs2.arg2,
    );
    Ok(())
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn set_syscall_num(pid: nix::unistd::Pid, val: usize) -> Result<(), PtraceError> {
    event!(Level::DEBUG, "Replacing with {}", val,);
    // https://stackoverflow.com/questions/63620203/ptrace-change-syscall-number-arm64
    let mut data = val;
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: &mut data as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<usize>(),
        };
        libc::ptrace(
            common::PTRACE_SETREGSET,
            libc::pid_t::from(pid),
            common::NT_ARM_SYSTEM_CALL as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::SetRegs)?;
    Ok(())
}

pub fn stack_ptr() -> usize {
    let mut ans: Option<usize> = None;
    backtrace::trace(|frame| {
        ans.replace(frame.sp() as usize);
        false
    });
    ans.unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use nix::sys::ptrace;
    use nix::sys::wait;
    use nix::unistd;
    use ntest::timeout;
    use std::thread;
    use std::time::Duration;

    fn _start_cmd() -> unistd::Pid {
        let mut cmd = std::process::Command::new("ls");
        let (pid, ..) = crate::start(&mut cmd, false).unwrap();
        pid
    }

    #[test]
    #[timeout(100)]
    fn test_start_cmd_does_wait_and_child_is_stopped() {
        let pid = _start_cmd();
        let status = crate::waitpid(pid.clone()).unwrap();
        assert!(matches!(status, wait::WaitStatus::StillAlive));
        assert!(!crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));
    }

    // Note: start() can only be called once. The following tests are disabled for now.

    //#[test]
    //#[timeout(100)]
    fn test_is_trace_stop_and_is_still_alive() {
        let pid = _start_cmd();
        ptrace::setoptions(pid.clone(), ptrace::Options::PTRACE_O_TRACEEXIT).unwrap();
        ptrace::cont(pid.clone(), None).unwrap();

        thread::sleep(Duration::from_millis(20)); // Note: without sleep, wait will return StillAlive instead.
        let status = crate::waitpid(pid.clone()).unwrap();
        assert!(matches!(status, wait::WaitStatus::PtraceEvent(_, _, _)));
        assert!(crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));
    }

    //#[test]
    //#[timeout(100)]
    fn test_child_finished_and_is_not_still_alive() {
        let pid = _start_cmd();
        let mut status = crate::waitpid(pid.clone()).unwrap();
        assert!(matches!(&status, &wait::WaitStatus::StillAlive));
        assert!(!crate::is_trace_stop(&status));
        assert!(crate::is_still_alive(&status));

        ptrace::detach(pid.clone(), None).unwrap();
        status = crate::waitpid_hang(pid.clone()).unwrap();
        assert!(!crate::is_trace_stop(&status));
        assert!(!crate::is_still_alive(&status));
    }
}
