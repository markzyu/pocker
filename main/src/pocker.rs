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

use anyhow::bail;
use bytes::Buf;
use clap::{Args, Parser, Subcommand};
use flate2::read::GzDecoder;
use pocker::{CLIError, LaunchOptions, canonicalize_clone, init_logging, launch_ptrace};
use pocker_sysaug::{PermsMode, RAW_SYSCALL_INFOS, SysAugArgs, display_err};
use std::path::PathBuf;
use tracing::{Level, event};

const LAYER_TYPE_TAR_GZ: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const LOCKFILE_RUNNING: &str = ".pocker-running";

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
        image: String,

        /// Give a different name to this instance of the container
        #[arg(long)]
        name: Option<String>,

        #[command(flatten)]
        launch: LaunchOptions,

        #[command(flatten)]
        download: ImageDownloadArgs,
    },
}

#[derive(Args, Clone, Debug)]
struct ImageDownloadArgs {
    /// Where to put the containers for pocker. Default is ~/.pocker/storage
    ///
    /// The content of storage will have this layout:
    /// * `/instances/<tag>/`          : the current layer of pocker instances
    /// * `/instances/<tag>.metadata/` : the current layer's metadata
    /// * `/layers/<hash>/`            : the layer downloaded from OCI registries
    /// * `/layers/<hash>.metadata/`   : the layer's metadata
    ///
    /// Please note that the same instance can have multiple "tags". This is to
    /// support CoW layers in the future. One instance can have two tags:
    /// * Instance name      : "hello"
    /// * Default rootfs tag : "hello.stable"
    /// * Cow rootfs tag     : "hello.cow"
    ///
    /// And each tag has an accompanying metadata folder.
    #[arg(long)]
    storage_path: Option<PathBuf>,

    #[arg(long, default_value_t = "docker.io".to_string())]
    registry_host: String,

    #[arg(long, default_value_t = "library".to_string())]
    registry_namespace: String,
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to initialize ring as the TLS provider");
    actual_main().map_err(display_err).unwrap();
}

fn actual_main() -> anyhow::Result<()> {
    // Initialize, parse args
    let _guard = init_logging();
    let args = CLIArgs::parse();
    match args.commands {
        Commands::Run {
            image,
            launch,
            name,
            download,
        } => {
            download_image(image, name, download)?;
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

type InstanceAndLayers = (PathBuf, Vec<PathBuf>);

fn download_image(image_name: String, instance_name: Option<String>, args: ImageDownloadArgs) -> anyhow::Result<InstanceAndLayers> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all() // Enables both the I/O driver and the time driver
        .build()?;

    // 2. Execute the future, blocking the current thread until completion
    let image: anyhow::Result<_> = rt.block_on(async {
        let client = oci_client::Client::default();
        let reference_str = format!(
            "{}/{}/{}",
            args.registry_host, args.registry_namespace, &image_name
        );
        let reference: oci_client::Reference = reference_str.parse()?;
        let auth = oci_client::secrets::RegistryAuth::Anonymous;
        let image = client
            .pull(&reference, &auth, vec![LAYER_TYPE_TAR_GZ])
            .await?;
        Ok(image)
    });
    let image = image?;

    let default_dir = std::env::home_dir().map(|p| p.join(".pocker").join("storage"));
    let Some(storage_dir) = args.storage_path.or(default_dir) else {
        bail!("Cannot establish default pocker storage at ~/.pocker/storage");
    };
    std::fs::create_dir_all(&storage_dir)?;

    let layers_dir = storage_dir.join("layers");
    let instances_dir = storage_dir.join("instances");
    let instance_name = instance_name.unwrap_or(image_name);
    let instance = instances_dir.join(&instance_name);
    let instance_running = instances_dir.join(LOCKFILE_RUNNING);
    if instance_running.exists() {
        bail!("Refusing to overwrite an existing, running instance: {}", &instance_name);
    }

    let mut layer_dirs: Vec<PathBuf> = Vec::new();
    for layer in image.layers {
        let digest = layer.sha256_digest();
        let layer_dir = layers_dir.join(&digest);
        layer_dirs.push(layer_dir.clone());

        if layer_dir.is_dir() {
            // TODO: verify folder content (path and size) at least
            event!(Level::DEBUG, "Skipping download of layer {}", &digest);
            continue;
        }

        if !layer.media_type.ends_with(".tar+gzip") {
            bail!("Unknown image format: {}", image.config.media_type);
        }

        let mut gz = GzDecoder::new(layer.data.reader());
        let mut tar = tar::Archive::new(&mut gz);
        tar.unpack(&layer_dir)?;
    }

    Ok((instance, layer_dirs))
}
