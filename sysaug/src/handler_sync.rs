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

use crate::common::{PTRACE_EVENT_SECCOMP, SysAugArgs, SysAugError, display_err, rwlock_read};
use crate::config::{SysAugConfig, init_passthroughs_from_config, init_perms_ids_from_config};
use crate::handler_async::{AsyncNotifications, AsyncTraceeHandler};
use krsm::AsyncYielder;
use nix::sys;
use nix::sys::utsname::uname;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use pocker_executor::{PtraceAsyncRuntime, PtraceFutureTypes, PtraceStatus};
use pocker_ptrace::{is_still_alive, is_trace_stop, waitpid_hang};
use std::cell::RefCell;
use std::collections::HashSet;
use std::os::fd::RawFd;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use sys::signal::Signal;
use tracing::{Level, event, info, span};

/// This is the synchronous event loop. It differs from the AsyncTraceeHandler in that:
///    * TraceeHandler focuses on handling actually "shared" states (between different threads / different tracees)
///    * TraceeHandler is aware of the threading model and make sure there is one thread per tracee
///    * TraceeHandler is unaware of what the next sysaug should do. AsyncTraceeHandler handles that.
pub struct TraceeHandler<PtraceClient: pocker_executor::PtraceClient> {
    // --------- Readonly, Copy on Move, values ---------
    pub pid: Pid,
    pub ptrace_client: PtraceClient,
    pub shared_fd: RawFd,
    pub mmap_tracer_addr: usize,

    // --------- Readonly, Reference-only values ---------
    /// These values are mostly constant within the same tracee PID.
    /// However, they can change for child processes. (child.consts != parent.consts)
    pub consts: Arc<TraceeHandlerConsts>,
    /// Storing the parent handler outside "consts" is optional but makes things easier.
    pub parent: Option<Arc<TraceeHandler<PtraceClient>>>,

    // --------- Actual shared states that are owned by this Thread ---------
    /// Whether the tracee has crashed due to tracer failures
    pub failed: AtomicBool,

    /// ignore the next sigstop for the following pids
    pub ignore_sigstops: Arc<RwLock<HashSet<Pid>>>,
}

#[derive(Clone, Debug)]
pub struct TraceeHandlerConsts {
    pub args: SysAugArgs,
    pub config: SysAugConfig,
    pub root_pid: Pid,
}

impl<PtraceClient: pocker_executor::PtraceClient> TraceeHandler<PtraceClient> {
    pub fn new(
        pid: Pid,
        ptrace_client: PtraceClient,
        consts: Option<Arc<TraceeHandlerConsts>>,
        parent: Option<Arc<TraceeHandler<PtraceClient>>>,
        shared_fd: RawFd,
        mmap_addr: usize,
    ) -> Result<Arc<TraceeHandler<PtraceClient>>, SysAugError> {
        let default_consts = consts.unwrap_or_default();
        Ok(Arc::new(TraceeHandler {
            pid,
            ptrace_client,
            shared_fd,
            mmap_tracer_addr: mmap_addr,

            consts: Arc::new((*default_consts).clone()),
            parent,

            failed: AtomicBool::new(false),
            ignore_sigstops: Arc::new(RwLock::default()),
        }))
    }

    /// Create a new TraceeHandler for a child, without starting event loop
    pub fn fork(
        self: &Arc<TraceeHandler<PtraceClient>>,
        child_pid: Pid,
    ) -> Result<Arc<TraceeHandler<PtraceClient>>, SysAugError> {
        TraceeHandler::new(
            child_pid,
            self.ptrace_client.clone(),
            Some(self.consts.clone()),
            Some(Arc::clone(self)),
            self.shared_fd,
            self.mmap_tracer_addr,
        )
    }

    fn set_ptrace_options(&self) -> Result<(), SysAugError> {
        let pid = self.pid;
        let status = waitpid_hang(pid)?;
        event!(Level::TRACE, "child status {:?}", &status);
        if !is_trace_stop(&status) && !is_still_alive(&status) {
            return Err(SysAugError::TraceeCrashed);
        }
        self.ptrace_client
            .execute(move || {
                sys::ptrace::setoptions(
                    pid,
                    sys::ptrace::Options::PTRACE_O_TRACESYSGOOD
                        | sys::ptrace::Options::PTRACE_O_TRACEEXIT
                        | sys::ptrace::Options::PTRACE_O_TRACECLONE
                        | sys::ptrace::Options::PTRACE_O_TRACEFORK
                        | sys::ptrace::Options::PTRACE_O_TRACEVFORK
                        | sys::ptrace::Options::PTRACE_O_TRACESECCOMP,
                )
            })?
            .map_err(SysAugError::PtraceSetOptions)?;
        Ok(())
    }

    pub fn trace_span(&self) -> tracing::Span {
        span!(Level::ERROR, "event_loop", "{:?}", self.pid)
    }

    pub fn start<F>(
        self: Arc<TraceeHandler<PtraceClient>>,
        callback: F,
    ) -> thread::JoinHandle<Option<u8>>
    where
        F: FnOnce() + Send + 'static,
    {
        let thread_name = format!("tracer-{}", self.pid);
        let new_thread = thread::Builder::new().name(thread_name);
        new_thread
            .spawn(move || {
                let self2 = Arc::clone(&self);
                let _span = self.trace_span().entered();
                let result = self.event_loop().map_err(display_err);
                if result.is_err() {
                    let _ =
                        sys::signal::kill(self2.pid, Some(Signal::SIGKILL)).map_err(display_err);
                    self2.failed.store(true, Ordering::Relaxed);
                }
                callback();
                result.ok()
            })
            .unwrap()
    }

    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    fn _ptrace_request_next_syscall(
        &self,
        maybe_signal: Option<Signal>,
        notifiers: &AsyncNotifications,
    ) -> Result<(), SysAugError> {
        let pid = self.pid;
        let is_single_syscall = { *notifiers.resume_through_syscall.borrow() };
        if is_single_syscall {
            event!(Level::DEBUG, "PTRACE_SYSCALL");
            self.ptrace_client
                .execute(move || sys::ptrace::syscall(pid, maybe_signal))?
                .map_err(SysAugError::PtraceSyscall)?;
        } else {
            event!(Level::DEBUG, "PTRACE_CONT");
            self.ptrace_client
                .execute(move || sys::ptrace::cont(pid, maybe_signal))?
                .map_err(SysAugError::PtraceContinue)?;
        }
        Ok(())
    }

    pub fn event_loop(self: &Arc<TraceeHandler<PtraceClient>>) -> Result<u8, SysAugError> {
        let pid = self.pid;

        // Initialize and store async loops and futures
        let async_runtime = PtraceAsyncRuntime::new();
        let async_handlers = AsyncTraceeHandler {
            async_runtime: &async_runtime,
            pid: pid.clone(),
            shared_fd: self.shared_fd.clone(),

            consts: (*self.consts).clone(),

            parent: self.parent.clone(),
            sync_handler: Arc::downgrade(&self),
            ptrace_client: self.ptrace_client.clone(),
            ignore_sigstops: self.ignore_sigstops.clone(),

            yielder_syscall: AsyncYielder::default(),
            notifiers: AsyncNotifications::default(),

            perms_ids: RefCell::default(),
            path_prefix: RefCell::default(),
            path_prefix_excludes: RefCell::default(),

            mmap_tracee_addr: RefCell::default(),
            tracee_stack_offset: RefCell::default(),
            is_after_syscall_entry: RefCell::default(),
            is_legacy_seccomp: RefCell::new({
                let uname_result = uname().map_err(SysAugError::ReadKernelVersion)?;
                let kernel_version = uname_result.release().to_string_lossy();
                let version_parts = kernel_version.split('.').collect::<Vec<&str>>();
                let maybe_error =
                    SysAugError::ParseKernelVersion(kernel_version.clone().to_string());
                let maybe_error2 =
                    SysAugError::ParseKernelVersion(kernel_version.clone().to_string());
                let major = version_parts[0].parse::<usize>().map_err(|_| maybe_error)?;
                let minor = version_parts[1]
                    .parse::<usize>()
                    .map_err(|_| maybe_error2)?;
                major <= 4 && minor <= 7
            }),
            tracee_seccomp_init_complete: RefCell::new(false),
            orig_syscall_num: RefCell::new(None),
        };

        // Initialize async states from config json
        init_perms_ids_from_config(&async_handlers.perms_ids, &self.consts.config.perms)?;
        if self.consts.args.chroot.is_some() {
            let mut path_prefix = async_handlers.path_prefix.borrow_mut();
            let mut path_prefix_excludes = async_handlers.path_prefix_excludes.borrow_mut();
            init_passthroughs_from_config(&mut *path_prefix_excludes, &self.consts.config.rootfs);
            *path_prefix = self.consts.args.chroot.clone();
        }

        let mut main_loop_future = pin!(async_handlers.all_tracee_loops());

        // Attach ptrace to tracee
        self.ptrace_client.attach_to(pid)?;
        self.set_ptrace_options()?;

        loop {
            // Drive async logic until it is pending on a future by resuming from where we left off
            let async_step_result = async_runtime.run_async_step(&mut main_loop_future);
            if let Some(exit_code) = async_step_result {
                // Handle signals, special gdb exit, etc
                if *async_handlers.notifiers.transfer_to_gdb.borrow() {
                    return Ok(self.transfer_to_gdb()?);
                }

                return Ok(exit_code?);
            }

            let mut maybe_signal = { async_handlers.notifiers.signal_tracee.borrow_mut().take() };

            loop {
                // Send ptrace calls, resume tracee, until we have unblocked a future
                // Also, use maybe_signal.take() so that the signal is only sent once
                self._ptrace_request_next_syscall(maybe_signal.take(), &async_handlers.notifiers)?;
                let wait_status = waitpid_hang(pid)?;
                event!(Level::TRACE, "child status {:?}", &wait_status);

                let status = PtraceStatus {
                    wait_status: wait_status.clone(),
                };

                // Handle unexpected crashes
                if !is_trace_stop(&wait_status) && !is_still_alive(&wait_status) {
                    info!("Process {:?} crashed: {:?}.", &pid, &wait_status);
                    self.ptrace_client
                        .execute(move || sys::ptrace::detach(pid, None))?
                        .map_err(SysAugError::PtraceDetach)?;
                    return Err(SysAugError::TraceeCrashed);
                }

                // Unblock different futures in the proper order
                if let Some(..) = self.get_tracee_maybe_signal(&wait_status)? {
                    async_runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, status);
                    break;
                } else if let WaitStatus::PtraceEvent(_, _, PTRACE_EVENT_SECCOMP) = &wait_status {
                    async_runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSeccomp, status);
                    break;
                } else if let WaitStatus::PtraceEvent(..) = &wait_status {
                    async_runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceEvent, status);
                    break;
                } else if let WaitStatus::PtraceSyscall(..) = &wait_status {
                    async_runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, status);
                    break;
                } else {
                    event!(Level::INFO, "Unknown ptrace event: {:?}", &wait_status);
                }
            }
        }
    }

    fn get_tracee_maybe_signal<'a>(
        &self,
        s: &'a WaitStatus,
    ) -> Result<Option<&'a Signal>, SysAugError> {
        let pid = self.pid;
        if let WaitStatus::Stopped(_, signal) = s {
            event!(Level::DEBUG, "child stopped, status {:?}", &s);
            if signal == &Signal::SIGTRAP {
                return Ok(None);
            }
            let getsig_ans = self
                .ptrace_client
                .execute(move || sys::ptrace::getsiginfo(pid))?;
            if getsig_ans.err() == Some(nix::errno::Errno::EINVAL) {
                return Ok(None);
            }
            return Ok(Some(signal));
        }
        Ok(None)
    }

    fn transfer_to_gdb(&self) -> Result<u8, SysAugError> {
        let pid = self.pid;
        self.ptrace_client
            .execute(move || sys::ptrace::detach(pid, Signal::SIGSTOP))?
            .map_err(SysAugError::GDBDetach)?;
        let mut cmd = std::process::Command::new("gdb");
        cmd.arg("-p").arg(pid.as_raw().to_string());
        let status = cmd.status().map_err(SysAugError::GDB)?;
        Ok(status.code().unwrap_or(-1) as u8)
    }
}

#[allow(dead_code)]
fn clone_locked<T: Clone>(lock: &RwLock<T>) -> Result<RwLock<T>, SysAugError> {
    let val = rwlock_read(lock)?;
    Ok(RwLock::new(val.clone()))
}

impl Default for TraceeHandlerConsts {
    fn default() -> TraceeHandlerConsts {
        TraceeHandlerConsts {
            args: SysAugArgs::default(),
            config: SysAugConfig::default(),
            root_pid: Pid::from_raw(0),
        }
    }
}
