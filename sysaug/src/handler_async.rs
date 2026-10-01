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

use crate::common::{
    Augments, NO_MOD_SYSCALL, PR_SET_NO_NEW_PRIVS, PTRACE_EVENT_SECCOMP, SECCOMP_FILTER_FLAG_TSYNC,
    SECCOMP_SET_MODE_FILTER, SI_CODE_SYS_SECCOMP, SYS_MMAP, SYS_MMAP_PGOFFSET_BLOCK, SysAugError,
    display_err, rwlock_read,
};
use crate::config::PERMS_IDS_SIZE;
use crate::handler_sync::{TraceeHandler, TraceeHandlerConsts};
use crate::syscalls::{BpfProgram, SECCOMP_FILTERS, SYSCALL_INSTRUCTION_SIZE, get_syscall};
use krsm::AsyncYielder;
use nix::sys;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use pocker_executor::{PtraceAsyncRuntime, PtraceFutureTypes, PtraceStatus};
use pocker_ptrace::{
    DIRECT_MEM_HELPERS, GenericPurposeRegs, MemHelpers, SLOW_MEM_HELPERS, STACK_SAFE_ZONE_SIZE,
    get_own_region_id, getevent, getregs, is_syscall_stop, set_syscall_num,
    set_tracee_write_region_addr, setregs,
};
use std::cell::RefCell;
use std::collections::HashSet;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::{Arc, RwLock, Weak};
use sys::signal::Signal;
use tracing::{Level, event, info};

thread_local! {
    static MEM: RefCell<MemHelpers> = const { RefCell::new(MemHelpers { ..SLOW_MEM_HELPERS }) };
}

pub fn get_mem_helper() -> MemHelpers {
    MEM.with_borrow(|cell| cell.clone())
}

/// Call augment without having to rely on the slow dyn Boxes
macro_rules! call_augment {
    ($self: ident, $augment: expr, $regs: expr, $syscall: expr) => {
        match $augment {
            Some(Augments::Clone) => $self.augment_sys_clone($regs, $syscall).await,
            Some(Augments::Exec) => $self.augment_sys_exec($regs, $syscall).await,
            Some(Augments::Paths) => $self.augment_sys_paths($regs, $syscall).await,
            Some(Augments::Perms) => $self.augment_sys_perms($regs, $syscall).await,
            Some(Augments::Waitpid) => $self.augment_sys_waitpid($regs, $syscall).await,
            Some(Augments::Seccomp) => $self.augment_sys_seccomp($regs, $syscall).await,
            Some(Augments::Unimplemented) => Err(SysAugError::UnimplementedAugment),
            _ => Ok(()),
        }
        .map_err(display_err)?;
    };
}

/// This is the asynchronous event loop. It is protected from Rust's threadsafety constraints,
/// (i.e. you don't need Arc/RwLock for internal states) because PtraceAsyncRuntime runs on a single, local thread.
pub struct AsyncTraceeHandler<'a, PtraceClient: pocker_executor::PtraceClient> {
    // --------- Readonly, Copy on Move, values ---------
    pub async_runtime: &'a PtraceAsyncRuntime,
    pub pid: Pid,
    pub shared_fd: RawFd,

    /// These consts would be copied from the sync handler's Arc<TraceeHandlerConsts>
    /// (Tradeoff is that reads don't need extra deref, but init of new tracee is slower)
    pub consts: TraceeHandlerConsts,

    // --------- References to other external states and helpers ---------
    pub parent: Option<Arc<TraceeHandler<PtraceClient>>>,
    pub sync_handler: Weak<TraceeHandler<PtraceClient>>,
    pub ptrace_client: PtraceClient,
    pub ignore_sigstops: Arc<RwLock<HashSet<Pid>>>,

    /// Yield until the next syscall poll has happened
    pub yielder_syscall: AsyncYielder,
    /// Notify the outside, synchronous event loop about states from async
    pub notifiers: AsyncNotifications,

    // --------- Actual shared states that are owned by this Async loop ---------
    pub perms_ids: RefCell<[Option<usize>; PERMS_IDS_SIZE]>,
    pub path_prefix: RefCell<Option<PathBuf>>,
    pub path_prefix_excludes: RefCell<Vec<PathBuf>>,

    pub mmap_tracee_addr: RefCell<usize>,
    pub tracee_stack_offset: RefCell<usize>,
    /// This tracks completion of either syscall-entry-stop or seccomp-stop
    pub is_after_syscall_entry: RefCell<bool>,

    /// Whether kernel version is < 4.8
    pub is_legacy_seccomp: RefCell<bool>,
    /// Whether seccomp has been initialized
    /// (note: this only matters for the root process. all children processes will already have seccomp initialized)
    pub tracee_seccomp_init_complete: RefCell<bool>,
    pub orig_syscall_num: RefCell<Option<usize>>,
}

/// Events reported from async loop back to the Runtime without resolving async loop
#[derive(Default)]
pub struct AsyncNotifications {
    /// Whether to resume through a PTRACE_CONT or PTRACE_SYSCALL (see `wait_for_syscall()`)
    pub resume_through_syscall: RefCell<bool>,
    pub signal_tracee: RefCell<Option<Signal>>,
    pub transfer_to_gdb: RefCell<bool>,
}

impl<PtraceClient: pocker_executor::PtraceClient> AsyncTraceeHandler<'_, PtraceClient> {
    /// Returns: the tracee exit code
    pub async fn all_tracee_loops(&self) -> Result<u8, SysAugError> {
        // Event loops
        // (The order here matters. It's the order of polling precedence.)
        let result = futures_lite::future::or(
            futures_lite::future::or(
                self.loop_handle_tracee_signals(),
                self.loop_handle_tracee_syscalls(),
            ),
            self.loop_handle_tracee_other_events(),
        )
        .await;

        // Cleanup
        let pid = self.pid;
        let MemHelpers { close_tracee, .. } = get_mem_helper();
        (close_tracee)(&pid)?;
        result
    }

    /// Creates a future from raw PtraceFuture to wait for any signal
    async fn wait_for_any_signal(&self) -> Result<Signal, SysAugError> {
        let status = self
            .async_runtime
            .new_pending_future(PtraceFutureTypes::WaitForSignal)
            .await
            .map_err(SysAugError::AsyncRuntime)?;
        if let WaitStatus::Stopped(_, signal) = status.wait_status {
            return Ok(signal);
        }
        Err(SysAugError::AsyncMismatch(
            PtraceFutureTypes::WaitForSignal,
            status.clone(),
        ))
    }

    /// Wait for a specific signal
    #[allow(dead_code)]
    async fn wait_for_signal(&self, signal: Signal) -> Result<(), SysAugError> {
        loop {
            let signal2 = self.wait_for_any_signal().await?;
            if signal == signal2 {
                return Ok(());
            }
        }
    }

    /// This function is used to wait for both syscall-entry-stop and syscall-exit-stop
    /// (This needs to handle the special case that seccomp has extra syscall-entry-stop for some kernel versions)
    /// Possibile starting states:
    ///    * Starts from seccomp            (yields until syscall-exit-stop)
    ///    * Starts from syscall-exit-stop  (yields until seccomp)
    ///
    /// Assupmtions:
    ///    * We will never start from syscall-entry-stop
    ///    * All injected system calls are also SECCOMP_RET_TRACE
    ///    * Nobody directly calls ptrace::syscall() to step through one syscall at a time
    ///    * We don't have access to PTRACE_GET_SYSCALL_INFO (kernel < 5.4)
    async fn wait_for_syscall(&self) -> Result<PtraceStatus, SysAugError> {
        let is_legacy = { *self.is_legacy_seccomp.borrow() };
        let is_seccomp_ready = { *self.tracee_seccomp_init_complete.borrow() };
        let expects_syscall_exit = self.is_after_syscall_entry.replace(false);
        let expects_syscall_stop = !is_seccomp_ready || expects_syscall_exit;

        // Run PTRACE_CONT / PTRACE_SYSCALL
        self.notifiers
            .resume_through_syscall
            .replace(expects_syscall_stop);

        // Wait for one round of syscall-*-stop OR seccomp-stop
        let future_type = if expects_syscall_stop {
            PtraceFutureTypes::WaitForPtraceSyscall
        } else {
            PtraceFutureTypes::WaitForPtraceSeccomp
        };
        let mut status = self
            .async_runtime
            .new_pending_future(future_type)
            .await
            .map_err(SysAugError::AsyncRuntime)?;

        if !is_seccomp_ready {
            if !is_syscall_stop(&status.wait_status) {
                return Err(SysAugError::AsyncMisMatchSyscall(
                    "non-syscall stop while initializing seccomp",
                    status.clone(),
                ));
            }
            return Ok(status.clone());
        }

        if let WaitStatus::PtraceEvent(_, _, PTRACE_EVENT_SECCOMP) = &status.wait_status {
            if expects_syscall_exit {
                return Err(SysAugError::AsyncMisMatchSyscall(
                    "seccomp stop right after seccomp stop",
                    status.clone(),
                ));
            }
            self.is_after_syscall_entry.replace(true);
            return Ok(status.clone());
        } else if is_syscall_stop(&status.wait_status) && expects_syscall_exit {
            if !is_legacy {
                self.is_after_syscall_entry.replace(false);
                return Ok(status.clone());
            }

            // We are in kernel version < 4.8 and need to do an extra round of ptrace_syscall (through async)
            self.is_after_syscall_entry.replace(false);
            self.notifiers.resume_through_syscall.replace(true);
            status = self
                .async_runtime
                .new_pending_future(PtraceFutureTypes::WaitForPtraceSyscall)
                .await
                .map_err(SysAugError::AsyncRuntime)?;

            if is_syscall_stop(&status.wait_status) {
                self.is_after_syscall_entry.replace(false);
                return Ok(status.clone());
            }
        }
        Err(SysAugError::AsyncMismatch(
            PtraceFutureTypes::WaitForPtraceSyscall,
            status.clone(),
        ))
    }

    /// Send the content of `bytes` to tracee's stack, and return its address.
    /// This can be called multiple times and will add new content to the end of
    /// previous contents.
    ///
    /// Note: By default, you don't need to clean up this stack, because the
    ///    `loop_handle_tracee_syscalls` function will cleanup before each syscall.
    pub fn tracee_stack_append(&self, bytes: Vec<u8>) -> Result<usize, SysAugError> {
        let MemHelpers {
            write_bytes_to_tracee,
            ..
        } = get_mem_helper();
        let pid = self.pid;
        let mut offset = self.tracee_stack_offset.borrow_mut();
        let old_offset = *offset;
        let (addr, new_offset) = self.ptrace_client.execute(move || {
            let final_bytes = bytes.as_slice();
            unsafe { (write_bytes_to_tracee)(pid, old_offset, final_bytes) }
        })??;
        *offset = new_offset;
        Ok(addr)
    }

    /// This is similar to tracee_stack_append, but it **destructs** an object into bytes and appends them.
    pub fn tracee_stack_append_fixed_size_obj<T: Sized>(
        &self,
        obj: T,
    ) -> Result<usize, SysAugError> {
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(&obj as *const _ as *const u8, std::mem::size_of::<T>())
        };
        self.tracee_stack_append(bytes.to_vec())
    }

    pub fn tracee_stack_append_str(&self, val: String) -> Result<usize, SysAugError> {
        let mut bytes: Vec<u8> = val.into();
        bytes.push(0);
        self.tracee_stack_append(bytes)
    }

    pub fn tracee_stack_append_path(&self, path: PathBuf) -> Result<usize, SysAugError> {
        let mut bytes = path.into_os_string().into_vec();
        bytes.push(0);
        self.tracee_stack_append(bytes)
    }

    /// Change the address, to which the next tracee_stack_append will write contents.
    /// offset = how many bytes of previously written contents will stay after this
    ///
    /// Note: By default, this is called upon every syscall entry
    pub fn tracee_stack_seek(&self, offset: usize) -> Result<(), SysAugError> {
        let mut ref_offset = self.tracee_stack_offset.borrow_mut();
        *ref_offset = offset;
        Ok(())
    }

    async fn loop_handle_tracee_signals(&self) -> Result<u8, SysAugError> {
        let pid = self.pid;
        loop {
            let signal = self.wait_for_any_signal().await?;
            let getsig_ans = self
                .ptrace_client
                .execute(move || sys::ptrace::getsiginfo(pid))?;
            if getsig_ans.err() == Some(nix::errno::Errno::EINVAL) {
                continue;
            }
            if signal == Signal::SIGSTOP {
                if let Some(parent) = self.parent.as_ref() {
                    let ignore_sigstops = rwlock_read(parent.ignore_sigstops.as_ref())?;
                    if ignore_sigstops.contains(&pid) {
                        continue;
                    }
                }
            }
            if signal == Signal::SIGSYS {
                // Android sometimes kills a process for using privileged syscalls
                // Instead of killing tracee, set retval to -ENOSYS
                let siginfo = getsig_ans.map_err(SysAugError::PtraceGetSigInfo2)?;
                let mut regs = self.ptrace_client.execute(move || getregs(pid))??;
                let is_seccomp =
                    !self.consts.args.no_seccomp && siginfo.si_code == SI_CODE_SYS_SECCOMP;
                let is_fix_sigsys = self.consts.args.fix_sigsys && siginfo.si_code > 0;
                if is_seccomp || is_fix_sigsys {
                    // Signal was sent by kernel, so it's safe to assume a syscall just happened.

                    // TODO: This is bad for security. Other processes can replace register by running
                    //              kill -NOSYS <tracee pid>
                    event!(
                        Level::WARN,
                        "blocking SIGSYS and returning ENOSYS instead (UNSAFE)",
                    );

                    // If we got this due to SECCOMP, let Augments handle the sysexit event
                    // (Note: we can't yield to the other loops here, because this sysexit is unexpected)
                    if is_seccomp {
                        let syscall_num = regs.syscall_num();
                        let (syscall_info, _) = get_syscall(syscall_num);
                        let which_aug = syscall_info.map(|x| &x.augment);
                        event!(
                            Level::WARN,
                            "SECCOMP SIGSYS handler, special sysexit for Augment {:?} ({})",
                            &which_aug,
                            syscall_num
                        );
                        if Some(&Augments::Perms) == which_aug {
                            let skip = self.do_sysenter_perms(&regs, syscall_info.unwrap())?;
                            if let Some(retval) = skip {
                                regs.set_syscall_retval(retval);
                                self.ptrace_client.execute(move || setregs(pid, regs))??;
                            } else {
                                self.do_sysexit_perms(regs.clone(), syscall_info.unwrap())?;
                            }
                        }
                        continue;
                    }

                    // If we were trying to override a syscall, follow that override.
                    if regs.syscall_num() == NO_MOD_SYSCALL {
                        self.yielder_syscall.yield_now().await;
                        continue;
                    }

                    // Otherwise, override return value to -ENOSYS
                    let retval = (-libc::ENOSYS) as usize;
                    regs.set_syscall_retval(retval);
                    self.ptrace_client.execute(move || setregs(pid, regs))??;

                    continue;
                }
            }
            if signal == Signal::SIGSEGV && self.consts.args.gdb {
                info!("Tracee segfault. Starting gdb");
                *self.notifiers.transfer_to_gdb.borrow_mut() = true;
                return Ok(0);
            }
            info!("Will deliver signal {:?} to {:?}", &signal, &pid);
            self.notifiers.signal_tracee.borrow_mut().replace(signal);
        }
    }

    async fn loop_handle_tracee_other_events(&self) -> Result<u8, SysAugError> {
        let pid = self.pid;
        loop {
            let status = self
                .async_runtime
                .new_pending_future(PtraceFutureTypes::WaitForPtraceEvent)
                .await
                .map_err(SysAugError::AsyncRuntime)?;

            // Tracee is being cloned or forked
            if matches!(
                status.wait_status,
                WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_CLONE)
                    | WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_FORK)
                    | WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_VFORK)
            ) {
                let raw_pid = self.ptrace_client.execute(move || getevent(pid))?? as isize;
                if raw_pid > 0 {
                    let child_pid: Pid = Pid::from_raw(raw_pid as i32);

                    self.ptrace_client
                        .prep_attach_to(child_pid, self.ignore_sigstops.as_ref())?;

                    let new_tracee_handler = self
                        .sync_handler
                        .upgrade()
                        .ok_or(SysAugError::WeakReference)?
                        .fork(child_pid)?;
                    let new_tracee_handler2 = Arc::clone(&new_tracee_handler);
                    let root_pid = self.consts.root_pid;
                    let fail_fast = self.consts.args.fail_fast;
                    new_tracee_handler.start(move || {
                        if fail_fast && new_tracee_handler2.failed() {
                            let _ = sys::signal::kill(root_pid, Some(Signal::SIGKILL))
                                .map_err(display_err);
                        }
                    });
                }
                continue;
            }

            // Tracee exited normally
            if let WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_EXIT) = status.wait_status {
                let rawret = self.ptrace_client.execute(move || getevent(pid))??;
                let retcode = (rawret as u32) >> 8;
                info!("Exit status = {}", retcode);
                self.ptrace_client
                    .execute(move || sys::ptrace::detach(pid, None))?
                    .map_err(SysAugError::PtraceDetach)?;
                return Ok(retcode as u8);
            }
        }
    }

    /// Resume the system call as is (using the current tracee register states)
    /// But only wait for this one system call to go through, and
    /// Return just early enough to override system call return value.
    pub async fn do_resume_syscall(&self) -> Result<GenericPurposeRegs, SysAugError> {
        let pid = self.pid;
        self.wait_for_syscall().await?;
        let regs = self.ptrace_client.execute(move || getregs(pid))??;
        event!(
            Level::TRACE,
            "syscall exit event, stack@{:x}, return {:#x} args {:#x} {:#x} {:#x}",
            pocker_ptrace::stack_ptr(),
            regs.syscall_retval(),
            regs.arg0,
            regs.arg1,
            regs.arg2
        );

        // Note: It might be wise to double check we got the expected augment
        //       But, it might also overcomplicate the do_skip_syscall logic
        Ok(regs)
    }

    /// Skip the system call (clobbering current tracee register states, setting sysret=0)
    pub async fn do_skip_syscall(&self, syscall_retval: usize) -> Result<(), SysAugError> {
        let pid = self.pid;
        event!(Level::INFO, "Attempting to skip syscall");
        self.ptrace_client
            .execute(move || set_syscall_num(pid, NO_MOD_SYSCALL))??;

        let mut regs = self.do_resume_syscall().await?;

        event!(
            Level::DEBUG,
            "Returning {} for skipped syscall, originally {}",
            syscall_retval,
            regs.syscall_retval()
        );
        regs.set_syscall_retval(syscall_retval);
        self.ptrace_client.execute(move || setregs(pid, regs))??;
        Ok(())
    }

    async fn loop_handle_tracee_syscalls(&self) -> Result<u8, SysAugError> {
        let pid = self.pid;
        let mut total_times: u64 = 0;
        let mut is_first_loop_after_init: bool = false;
        loop {
            // We just finished one round of syscall. Unblock any signal handler that yielded to us
            self.yielder_syscall.unblock();
            total_times += 1;

            // Wait for System Call Entry
            self.wait_for_syscall().await?;
            self.orig_syscall_num.replace(None);
            let regs = self.ptrace_client.execute(move || getregs(pid))??;
            let (maybe_syscall_info, syscall_name) = get_syscall(regs.syscall_num());
            let which_aug = maybe_syscall_info.map(|x| &x.augment);
            event!(
                Level::DEBUG,
                "SYSCALL ENTRY: augment {:?} syscall {} id {} args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
                which_aug.unwrap_or(&Augments::None),
                syscall_name,
                total_times,
                regs.arg0,
                regs.arg1,
                regs.arg2,
                regs.arg3,
                regs.arg4,
                regs.arg5
            );
            event!(
                Level::TRACE,
                "syscall entry event, stack@{:x}",
                pocker_ptrace::stack_ptr()
            );

            self.tracee_stack_seek(0)?;

            if self.consts.args.gdb_at == Some(total_times) {
                info!(
                    "Reached {:?}-th system call. Starting gdb",
                    self.consts.args.gdb_at
                );
                *self.notifiers.transfer_to_gdb.borrow_mut() = true;
                return Ok(0);
            }

            // AFTER System Call Entry:
            // Update tracee_seccomp_init_complete when init is complete & when orig syscall completes
            if is_first_loop_after_init {
                self.tracee_seccomp_init_complete
                    .replace(!self.consts.args.no_seccomp);
                self.is_after_syscall_entry.replace(true);
                is_first_loop_after_init = false;
            }

            // Augment the system call or resume (This will yield AFTER System Call Exit)
            if let Some(syscall_info) = maybe_syscall_info {
                call_augment!(self, which_aug, regs.clone(), &syscall_info);
            } else {
                self.do_resume_syscall().await?;
            }

            // aarch64 doesn't work if we read regs right after execve()
            // Yet, x86_64 requires it...
            let _new_regs = self.ptrace_client.execute(move || getregs(pid))??;
            let (_new_syscall_info, _) = get_syscall(_new_regs.syscall_num());
            #[cfg(not(any(target_arch = "aarch64")))]
            let which_aug = _new_syscall_info.map(|x| &x.augment);

            if which_aug == Some(&Augments::Exec) {
                if !self.consts.args.fix_mmap {
                    self.initialize_tracee_mmaps().await?;
                }
                if self.parent.is_none() {
                    self.initialize_tracee_seccomp().await?;
                }
                is_first_loop_after_init = true;
            }
        }
    }

    /// This function can only be called during Tracee Initialization
    async unsafe fn _insert_syscall_during_init(
        &self,
        syscall_name: &'static str,
        syscall_num: usize,
        args: [usize; 6],
    ) -> Result<GenericPurposeRegs, SysAugError> {
        // Note: This function must call self.yielder_syscall.unblock() manually
        //       So that signal handlers and non-syscall ptrace code can still run.
        let pid = self.pid;

        // Wait for the next system call entry, could be anything, including NO_MOD_SYSCALL
        // (This won't cause a race on tracer side because:)
        //    1. Tracee has not yet run the inserted syscall
        //    2. Tracer loop_handle_tracee_syscalls() will not see any syscall until _insert_syscall_during_init() yields.
        //    3. The syscall we get from wait_for_syscall() will not complete until _insert_syscall_during_init() yields.
        //    4. When _insert_syscall_during_init() yields, both tracer and tracee will see the same syscall instead of the inserted one.
        self.yielder_syscall.unblock();
        self.wait_for_syscall().await?;

        let orig_regs = self.ptrace_client.execute(move || getregs(pid))??;
        let mut regs = orig_regs.clone();

        let clone_orig_syscall_num = { self.orig_syscall_num.borrow().clone() };
        let orig_syscall_num = if let Some(val) = clone_orig_syscall_num {
            val
        } else {
            let (_, orig_syscall_name) = get_syscall(regs.syscall_num());
            self.orig_syscall_num.replace(Some(regs.syscall_num()));
            event!(
                Level::INFO,
                "TraceeInit: Overriding first syscall, was {:?}",
                orig_syscall_name
            );
            regs.syscall_num()
        };

        // Override that system call to run mmap instead
        regs.arg0 = args[0];
        regs.arg1 = args[1];
        regs.arg2 = args[2];
        regs.arg3 = args[3];
        regs.arg4 = args[4];
        regs.arg5 = args[5];

        self.ptrace_client.execute(move || setregs(pid, regs))??;
        self.ptrace_client
            .execute(move || set_syscall_num(pid, syscall_num))??;

        // Wait for mmap to return
        event!(
            Level::DEBUG,
            "TraceeInit: executing replacement syscall {}",
            syscall_name
        );
        self.yielder_syscall.unblock();
        self.wait_for_syscall().await?;
        let result_regs = self.ptrace_client.execute(move || getregs(pid))??;

        // Reset tracee to register state before system call
        // and decrement PC pointer to immediately rerun system call
        // (Note: This doesn't actually resume the syscall, so it's ok to call _insert_syscall_during_init() again)
        let mut new_regs = orig_regs;
        new_regs.pc -= SYSCALL_INSTRUCTION_SIZE;
        event!(
            Level::DEBUG,
            "TraceeInit: Continuing syscall {} from {:x}",
            new_regs.syscall_num(),
            new_regs.pc
        );
        self.ptrace_client
            .execute(move || setregs(pid, new_regs))??;
        self.ptrace_client
            .execute(move || set_syscall_num(pid, orig_syscall_num))??;
        Ok(result_regs)
    }

    /// Take over the syscall async loop, right after execve() to establish mmap
    async fn initialize_tracee_mmaps(&self) -> Result<(), SysAugError> {
        let pid = self.pid;
        let region_id = get_own_region_id(&pid)?;
        let mmap_regs = unsafe {
            self._insert_syscall_during_init(
                "SYS_mmap",
                SYS_MMAP,
                [
                    0,
                    STACK_SAFE_ZONE_SIZE,
                    libc::PROT_READ as usize,
                    libc::MAP_SHARED as usize,
                    self.shared_fd as usize,
                    region_id * STACK_SAFE_ZONE_SIZE / SYS_MMAP_PGOFFSET_BLOCK,
                ],
            )
            .await?
        };

        let mut tracee_addr = self.mmap_tracee_addr.borrow_mut();
        *tracee_addr = mmap_regs.syscall_retval();

        set_tracee_write_region_addr(mmap_regs.syscall_retval())?;
        if !self.consts.args.fix_mmap {
            MEM.with_borrow_mut(|cell| *cell = DIRECT_MEM_HELPERS);
        }

        event!(
            Level::INFO,
            "Tracee mounted mmap address: {:x}",
            mmap_regs.syscall_retval()
        );
        Ok(())
    }

    async fn initialize_tracee_seccomp(&self) -> Result<(), SysAugError> {
        if self.consts.args.no_seccomp {
            event!(
                Level::WARN,
                "Skipping SECCOMP setup. This tracer will be slow."
            );
            return Ok(());
        }

        let prctl_regs = unsafe {
            self._insert_syscall_during_init(
                "SYS_prctl",
                libc::SYS_prctl as usize,
                [PR_SET_NO_NEW_PRIVS as usize, 1, 0, 0, 0, 0],
            )
            .await?
        };
        if prctl_regs.syscall_retval() != 0 {
            return Err(SysAugError::SeccompInit);
        }

        let filters_len = SECCOMP_FILTERS.actual_len;
        let filters_addr = self.tracee_stack_append_fixed_size_obj(SECCOMP_FILTERS.filters)?;

        let program = BpfProgram {
            len: filters_len as u16,
            filters_ptr: filters_addr,
        };
        let program_addr = self.tracee_stack_append_fixed_size_obj(program)?;

        let seccomp_regs = unsafe {
            self._insert_syscall_during_init(
                "SYS_seccomp",
                libc::SYS_seccomp as usize,
                [
                    SECCOMP_SET_MODE_FILTER as usize,
                    SECCOMP_FILTER_FLAG_TSYNC as usize,
                    program_addr,
                    0,
                    0,
                    0,
                ],
            )
            .await?
        };
        if seccomp_regs.syscall_retval() != 0 {
            event!(
                Level::ERROR,
                "Tracee failed to initialize seccomp, syscall retval: {:x}",
                seccomp_regs.syscall_retval()
            );
            return Err(SysAugError::SeccompInit);
        }
        event!(
            Level::INFO,
            "Tracee initialized seccomp with default filters, length {}",
            filters_len
        );
        Ok(())
    }
}
