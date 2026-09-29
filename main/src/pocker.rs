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

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use flate2::read::GzDecoder;
use oci_client::{
    client::{Certificate, CertificateEncoding},
    manifest::ImageIndexEntry,
};
use oci_spec::image::{Arch, Os};
use pocker::{CLIError, LaunchOptions, canonicalize_clone, init_logging, launch_ptrace};
use pocker_ptrace::setup_shared_memory;
use pocker_sysaug::{PermsMode, RAW_SYSCALL_INFOS, SysAugArgs};
use std::os::fd::AsRawFd;
use std::{ffi::OsString, io::Write};
use std::{os::fd::RawFd, path::PathBuf};
use tracing::{Level, event};
use webpki_root_certs::TLS_SERVER_ROOT_CERTS;

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

        /// An optional command to run. This defaults to /bin/sh, for now, not the one specified in the image.
        cmd: Option<String>,

        /// Give a different name to this instance of the container
        #[arg(long)]
        name: Option<String>,

        #[command(flatten)]
        launch: LaunchOptions,

        #[command(flatten)]
        download: ImageDownloadArgs,
    },
    /// Download a container from image name, and unarchive with fake permissions in mind
    Download {
        /// The name of the container image
        image: String,

        /// This is an internal option. Please do not use it unless you know what you're doing.
        #[arg(long)]
        internal_layer: Option<String>,

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

impl ImageDownloadArgs {
    fn push_os_strings(&self, ans: &mut Vec<OsString>) -> () {
        if let Some(path) = self.storage_path.as_ref() {
            ans.push("--storage-path".into());
            ans.push(path.clone().into_os_string());
        }
        ans.push("--registry-host".into());
        ans.push(self.registry_host.clone().into());

        ans.push("--registry-namespace".into());
        ans.push(self.registry_namespace.clone().into());
    }
}

fn main() -> anyhow::Result<()> {
    // Initialize, parse args
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to initialize ring as the TLS provider");
    let _guard = init_logging();
    let args = CLIArgs::parse();
    match args.commands {
        Commands::Run {
            image,
            cmd,
            launch,
            name,
            download,
        } => {
            let (shared_fd, mmap_addr) = setup_shared_memory().context("Preparing ptrace")?;
            event!(Level::INFO, "Downloading image...");
            let storage_dir = get_storage_dir(&download)?;
            let layers = download_image(
                image.clone(),
                &launch,
                download,
                shared_fd.as_raw_fd(),
                mmap_addr,
            )?;

            event!(Level::INFO, "Creating instance...");
            let instances_dir = storage_dir.join("instances");
            let instance_name = name.unwrap_or(image);
            let instance = instances_dir.join(&instance_name);
            let instance_running = instances_dir.join(LOCKFILE_RUNNING);
            if instance_running.exists() {
                bail!(
                    "Refusing to overwrite an existing, running instance: {}",
                    &instance_name
                );
            }

            event!(Level::INFO, "Running instance...");
            std::fs::create_dir_all(&instance).context("Failed to create instance dir")?;
            let lockfile = instance.join(LOCKFILE_RUNNING);
            {
                let mut file =
                    std::fs::File::create(&lockfile).context("Failed to lock instance")?;
                writeln!(file, "")?;
            }

            let cmd = cmd.unwrap_or("/bin/sh".to_string());
            let result = run_instance(
                cmd,
                &launch,
                instance,
                layers,
                shared_fd.as_raw_fd(),
                mmap_addr,
            );

            event!(Level::INFO, "Cleaning up...");
            std::fs::remove_file(&lockfile).context("Failed to unlock instance")?;

            let retcode = result?;
            event!(Level::INFO, "Done.");
            std::process::exit(retcode.unwrap() as i32);
        }
        Commands::Download {
            image,
            internal_layer,
            launch,
            download,
        } => {
            if let Some(layer) = internal_layer {
                event!(Level::INFO, "Downloading layer {}...", &layer);
                download_layer_from_tracee(layer, &download)?;
            } else {
                let (shared_fd, mmap_addr) = setup_shared_memory().context("Preparing ptrace")?;
                download_image(image, &launch, download, shared_fd.as_raw_fd(), mmap_addr)?;
            }
            Ok(())
        }
    }
}

fn get_oci_client() -> oci_client::Client {
    let certs: Vec<_> = TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|item| Certificate {
            encoding: CertificateEncoding::Der,
            data: Vec::from(item.as_ref()),
        })
        .collect();

    oci_client::Client::new(oci_client::client::ClientConfig {
        tls_certs_only: certs,
        platform_resolver: Some(Box::new(resolver_for_linux)),
        ..Default::default()
    })
}

/// Tell oci_client we are on Linux, even if it thinks that we are Android
fn resolver_for_linux(manifests: &[ImageIndexEntry]) -> Option<String> {
    manifests
        .iter()
        .find(|entry| {
            entry.platform.as_ref().is_some_and(|platform| {
                platform.os == Os::Linux && platform.architecture == Arch::default()
            })
        })
        .map(|entry| entry.digest.clone())
}

fn download_layer_from_tracee(layer: String, download: &ImageDownloadArgs) -> anyhow::Result<()> {
    let storage_dir = get_storage_dir(&download)?;
    let layers_dir = storage_dir.join("layers");
    let tar_name = format!("{}.tar.gz", layer);
    let layer_tar = layers_dir.join(tar_name);
    let layer_dir = layers_dir.join(&layer);

    let tar_file = std::fs::File::open(layer_tar)?;
    let mut gz = GzDecoder::new(tar_file);
    let mut tar = tar::Archive::new(&mut gz);
    tar.unpack(&layer_dir)?;
    Ok(())
}

fn get_storage_dir(args: &ImageDownloadArgs) -> anyhow::Result<PathBuf> {
    let default_dir = std::env::home_dir().map(|p| p.join(".pocker").join("storage"));
    let Some(storage_dir) = args.storage_path.clone().or(default_dir) else {
        bail!("Cannot establish default pocker storage at ~/.pocker/storage");
    };
    std::fs::create_dir_all(&storage_dir)?;
    Ok(storage_dir)
}

fn download_image(
    image_name: String,
    launch: &LaunchOptions,
    args: ImageDownloadArgs,
    shared_fd: RawFd,
    mmap_addr: usize,
) -> anyhow::Result<Vec<PathBuf>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all() // Enables both the I/O driver and the time driver
        .build()?;

    // 2. Execute the future, blocking the current thread until completion
    let image: anyhow::Result<_> = rt.block_on(async {
        let client = get_oci_client();
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

    let storage_dir = get_storage_dir(&args)?;
    let layers_dir = storage_dir.join("layers");

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

        let tar_name = format!("{}.tar.gz", &digest);
        let layer_tar = layers_dir.join(&tar_name);
        std::fs::create_dir_all(&layer_dir)?;
        std::fs::write(&layer_tar, layer.data).context("Saving layer tarfile")?;

        event!(Level::INFO, "Starting layer download {}", &digest);
        let self_path = std::env::current_exe()?.canonicalize()?;
        let args2 = SysAugArgs {
            chroot: None,
            rootfs: Some(layer_dir.clone()),
            perms_mode: PermsMode::RootOnly,
            fail_fast: launch.fail_fast,
            fix_sigsys: launch.fix_sigsys,
            fix_mmap: launch.fix_mmap || launch.fix_attach,
            no_seccomp: launch.no_seccomp,
            gdb: launch.gdb,
            gdb_at: launch.gdb_at,
            use_native_loader: launch.use_native_loader,
        };

        let fix_attach = launch.fix_attach;
        let mut cmd = std::process::Command::new(&self_path);
        let mut new_args: Vec<OsString> = Vec::new();
        new_args.push("download".into());
        new_args.push(image_name.clone().into());
        new_args.push("--internal-layer".into());
        new_args.push(digest.into());
        args.push_os_strings(&mut new_args);
        cmd.args(new_args);

        if let Err(e) = launch_ptrace(args2, cmd, fix_attach, shared_fd, mmap_addr) {
            bail!("Error: {:?}", e);
        }
    }

    Ok(layer_dirs)
}

fn run_instance(
    cmd: String,
    args: &LaunchOptions,
    instance: PathBuf,
    layers: Vec<PathBuf>,
    shared_fd: RawFd,
    mmap_addr: usize,
) -> anyhow::Result<Option<u8>> {
    let instance = instance.canonicalize()?;
    let args2 = SysAugArgs {
        chroot: Some(instance.clone()),
        rootfs: Some(instance),
        perms_mode: PermsMode::RootOnly,
        fail_fast: args.fail_fast,
        fix_sigsys: args.fix_sigsys,
        fix_mmap: args.fix_mmap || args.fix_attach,
        no_seccomp: args.no_seccomp,
        gdb: args.gdb,
        gdb_at: args.gdb_at,
        use_native_loader: args.use_native_loader,
    };

    let cmd = std::process::Command::new(&cmd);
    match launch_ptrace(args2, cmd, args.fix_attach, shared_fd, mmap_addr) {
        Err(e) => bail!("Error: {:?}", e),
        Ok(ans) => Ok(ans),
    }
}
