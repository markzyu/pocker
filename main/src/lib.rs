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

use clap::Args;
use pocker_executor::PtraceServer;
use pocker_sysaug::SysAugArgs;
use std::sync::Arc;
use std::thread;
use std::{os::fd::RawFd, path::PathBuf};
use thiserror::Error;
use tracing::{Level, event};
use tracing_appender::non_blocking::WorkerGuard;

#[derive(Debug, Error)]
pub enum CLIError {
    #[error("Unexpected internal error from ptrace() executor: {0}")]
    InternalExecutor(#[from] pocker_executor::PtraceExecutorError),

    #[error("Ptrace error: {0}")]
    Ptrace(#[from] pocker_ptrace::PtraceError),

    #[error("Syscall error: {0}")]
    SysAugErr(#[from] pocker_sysaug::SysAugError),

    #[error("Invalid command line arguments: {0}")]
    ParseArgs(String),

    #[error("Unable to complete")]
    UnableToComplete,

    #[error("Unable to find the absolute path of {0:?}: {1}")]
    PathCanonicalization(PathBuf, std::io::Error),

    #[error("Unable to pull image: {0:?}")]
    OciPull(oci_client::errors::OciDistributionError),

    #[error("Unknown image format: {0}")]
    OciImageFormat(String),
}

#[derive(Args, Clone, Debug)]
#[group(required = false, multiple = true)]
/// These options are reused in any command that launches containers
pub struct LaunchOptions {
    /// Only use this flag if you see "PTRACE_ATTACH error: EPERM: Permission denied".
    /// This will solve those permission errors, but will also cause slowdowns.
    /// (implies --fix-mmap)
    #[arg(long)]
    pub fix_attach: bool,

    /// If your tracee crashes due to SIGSYS, use this flag.
    #[arg(long)]
    pub fix_sigsys: bool,

    /// If your kernel is older than v3.17, then please use this flag to avoid mmap errors
    #[arg(long)]
    pub fix_mmap: bool,

    /// Disable SECCOMP. This slows things down a lot but helps with gdb / debugging
    #[arg(long)]
    pub no_seccomp: bool,

    /// Quit as soon as any application fails
    #[arg(long)]
    pub fail_fast: bool,

    /// Try to attach GDB to applications that crashed
    #[arg(long)]
    pub gdb: bool,

    /// Attach GDB after X number of system calls
    #[arg(long)]
    pub gdb_at: Option<u64>,

    /// Use the host ld.so instead of the one from the chroot environment
    #[arg(long)]
    pub use_native_loader: bool,
}

/// Note: for shared_fd, you must pass in a clone
pub fn launch_ptrace(
    args: SysAugArgs,
    cmd: std::process::Command,
    fix_attach: bool,
    shared_fd: RawFd,
    mmap_addr: usize,
) -> Result<Option<u8>, CLIError> {
    if fix_attach {
        let (ptrace_client, ptrace_loop) = pocker_executor::new_main_thread_executor();
        let join = launch_ptrace_with(args, cmd, fix_attach, ptrace_client, shared_fd, mmap_addr)?;
        ptrace_loop.serve()?;
        join.join().map_err(|_| CLIError::UnableToComplete)
    } else {
        let ptrace_client = pocker_executor::new_local_executor();
        launch_ptrace_with(args, cmd, fix_attach, ptrace_client, shared_fd, mmap_addr)?
            .join()
            .map_err(|_| CLIError::UnableToComplete)
    }
}

/// Note: for shared_fd, you must pass in a clone
fn launch_ptrace_with<PtraceClient: pocker_executor::PtraceClient>(
    args: SysAugArgs,
    mut cmd: std::process::Command,
    fix_attach: bool,
    ptrace_client: PtraceClient,
    shared_fd: RawFd,
    mmap_addr: usize,
) -> Result<thread::JoinHandle<Option<u8>>, CLIError> {
    // Spawn first tracee
    let pid1 = { pocker_ptrace::start(&mut cmd, fix_attach)? };
    event!(Level::INFO, "First tracee pid: {:?}", pid1);

    // Setup tracee handler states
    let states = pocker_sysaug::TraceeHandlerConsts {
        args,
        root_pid: pid1,
        ..Default::default()
    };

    // Start tracee handler thread
    let ptrace_client2 = ptrace_client.clone();
    let new_tracee_handler = pocker_sysaug::TraceeHandler::new(
        pid1,
        ptrace_client,
        Some(Arc::new(states)),
        None,
        shared_fd,
        mmap_addr,
    )?;
    Ok(new_tracee_handler.start(move || ptrace_client2.stop()))
}

pub fn canonicalize_clone(maybe_path: &Option<PathBuf>) -> Result<Option<PathBuf>, CLIError> {
    if let Some(path) = maybe_path {
        match path.canonicalize() {
            Ok(new_path) => Ok(Some(new_path)),
            Err(e) => Err(CLIError::PathCanonicalization(path.clone(), e)),
        }
    } else {
        Ok(None)
    }
}

pub fn init_logging() -> Option<WorkerGuard> {
    let no_color = std::env::var("RUST_LOG_NO_COLOR").is_ok();
    let is_blocking = std::env::var("RUST_LOG_BLOCKING").is_ok();
    let mut guard: Option<WorkerGuard> = None;
    if let Ok(filename) = std::env::var("RUST_LOG_DIR") {
        let appender = tracing_appender::rolling::minutely(filename, "main.log");
        let builder = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());
        if is_blocking {
            builder
                .with_writer(appender)
                .try_init()
                .expect("Unable to setup logging");
        } else {
            let (non_blocking1, guard1) = tracing_appender::non_blocking(appender);
            guard.replace(guard1);
            builder
                .with_writer(non_blocking1)
                .try_init()
                .expect("Unable to setup logging");
        };
        return guard;
    }

    let builder = tracing_subscriber::fmt()
        .with_ansi(!no_color)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());
    if is_blocking {
        builder
            .with_writer(std::io::stderr)
            .try_init()
            .expect("Unable to setup logging");
    } else {
        let stderr = std::io::stderr();
        let (non_blocking1, guard1) = tracing_appender::non_blocking(stderr);
        guard.replace(guard1);
        builder
            .with_writer(non_blocking1)
            .try_init()
            .expect("Unable to setup logging");
    };
    return guard;
}
