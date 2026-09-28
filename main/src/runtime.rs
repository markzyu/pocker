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

use clap::Parser;
use pocker::{CLIError, LaunchOptions, canonicalize_clone, launch_ptrace};
use pocker_sysaug::{PermsMode, RAW_SYSCALL_INFOS, SysAugArgs, display_err};
use std::path::PathBuf;
use tracing::{Level, event};

#[derive(Parser, Debug)]
#[command(version = "0.2.0", author = "Zhongzhi Yu")]
pub struct CLIArgs {
    /// Trace syscalls like strace (slow). Not all syscalls are supported.
    #[arg(long)]
    pub strace: bool,

    /// Chroot to this path upon tracee startup. Implies --rootfs
    #[arg(long)]
    pub chroot: Option<PathBuf>,

    /// Make your applications think they are root when they are not.
    #[arg(long)]
    pub root: bool,

    /// You probably want --chroot instead. This simulates rootfs without chroot, for files in this folder.
    #[arg(long)]
    pub rootfs: Option<PathBuf>,

    /// Make your applications think they can sudo when they cannot. Not compatible with --root
    #[arg(long)]
    pub sudo: bool,

    /// Do not start a pocker container. Instead, print the list of known syscalls
    #[arg(long)]
    pub show_syscalls: bool,

    /// Override the command to execute
    #[arg(long, default_value = "bash")]
    pub cmd: String,

    #[command(flatten)]
    pub launch: LaunchOptions,
}

fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    if let Ok(filename) = std::env::var("RUST_LOG_DIR") {
        let appender = tracing_appender::rolling::minutely(filename, "main.log");
        let (non_blocking1, guard1) = tracing_appender::non_blocking(appender);
        tracing_subscriber::fmt()
            .with_writer(non_blocking1)
            .with_ansi(false)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init()
            .expect("Unable to setup logging");
        return guard1;
    }
    let (non_blocking2, guard2) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::fmt()
        .with_writer(non_blocking2)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .expect("Unable to setup logging");
    return guard2;
}

fn main() {
    actual_main().map_err(display_err).unwrap();
}

fn actual_main() -> Result<(), CLIError> {
    // Initialize, parse args
    let _guard = init_logging();
    let args = CLIArgs::parse();

    if args.show_syscalls {
        for maybe_syscall in RAW_SYSCALL_INFOS.iter() {
            if let Some(syscall) = maybe_syscall {
                println!("{}: {:?}", syscall.name, syscall);
            }
        }
        return Ok(());
    }

    if args.root && args.sudo {
        event!(Level::ERROR, "You cannot use both --root and --sudo");
        return Ok(());
    }
    if args.chroot.is_some() && args.rootfs.is_some() {
        event!(Level::ERROR, "You cannot use both --chroot and --rootfs");
        return Ok(());
    }

    let launch_args = &args.launch;
    let chroot_copy = canonicalize_clone(&args.chroot)?;
    let args2 = SysAugArgs {
        chroot: canonicalize_clone(&args.chroot)?,
        rootfs: canonicalize_clone(&args.rootfs)?.or_else(|| chroot_copy),
        perms_mode: if args.root {
            PermsMode::RootOnly
        } else if args.sudo {
            PermsMode::SudoOnly
        } else {
            PermsMode::Passthrough
        },
        fail_fast: launch_args.fail_fast,
        fix_sigsys: launch_args.fix_sigsys,
        fix_mmap: launch_args.fix_mmap || launch_args.fix_attach,
        gdb: launch_args.gdb,
        gdb_at: launch_args.gdb_at,
        use_native_loader: launch_args.use_native_loader,
    };

    let retcode = launch_ptrace(args2, &args.cmd, launch_args.fix_attach)?;
    event!(Level::INFO, "Done. (all tracees exited)");
    std::process::exit(retcode.unwrap() as i32);
}
