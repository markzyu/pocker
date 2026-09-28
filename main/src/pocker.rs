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

use bytes::Buf;
use clap::{Args, Parser, Subcommand};
use flate2::read::GzDecoder;
use pocker::{CLIError, LaunchOptions, canonicalize_clone, init_logging, launch_ptrace};
use pocker_sysaug::{PermsMode, RAW_SYSCALL_INFOS, SysAugArgs, display_err};
use std::path::PathBuf;
use tracing::{Level, event};

const LAYER_TYPE_TAR_GZ: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

#[derive(Parser, Debug)]
#[command(version = "0.2.0", author = "Zhongzhi Yu")]
struct CLIArgs {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Clone, Debug, Subcommand)]
enum Commands {
    /// Download and run a container from image name
    Run {
        /// The name of the container image
        image_name: String,

        #[command(flatten)]
        launch: LaunchOptions,

        #[command(flatten)]
        download_args: ImageDownloadArgs,
    },
}

#[derive(Args, Clone, Debug)]
struct ImageDownloadArgs {
    /// Where to put the runtime rootfs for the container. Default is ./<image name>
    #[arg(long)]
    container_path: Option<PathBuf>,

    #[arg(long, default_value_t = "docker.io".to_string())]
    registry_host: String,

    #[arg(long, default_value_t = "library".to_string())]
    registry_namespace: String,
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");
    actual_main().map_err(display_err).unwrap();
}

fn actual_main() -> Result<(), CLIError> {
    // Initialize, parse args
    let _guard = init_logging();
    let args = CLIArgs::parse();
    match args.commands {
        Commands::Run {
            image_name,
            launch,
            download_args,
        } => {
            download_image(image_name, &download_args)?;
        }
    }

    /*
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
    */
    Ok(())
}

fn download_image(name: String, args: &ImageDownloadArgs) -> Result<PathBuf, CLIError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all() // Enables both the I/O driver and the time driver
        .build()
        .unwrap();

    // 2. Execute the future, blocking the current thread until completion
    let image: Result<_, CLIError> = rt.block_on(async {
        let client = oci_client::Client::default();
        let reference_str = format!(
            "{}/{}/{}",
            args.registry_host, args.registry_namespace, name
        );
        let reference: oci_client::Reference = reference_str.parse().unwrap();
        let auth = oci_client::secrets::RegistryAuth::Anonymous;
        let image = client
            .pull(&reference, &auth, vec![LAYER_TYPE_TAR_GZ])
            .await
            .map_err(CLIError::OciPull)?;
        Ok(image)
    });
    let image = image?;

    for layer in image.layers {
        let mut gz = GzDecoder::new(layer.data.reader());
        let mut tar = tar::Archive::new(&mut gz);
        for entry in tar.entries().unwrap() {
            println!("{:?}", entry.unwrap().path());
        }
    }

    Ok(PathBuf::new())
}
