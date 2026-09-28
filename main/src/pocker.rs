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
use bytes::Buf;
use clap::{Args, Parser, Subcommand};
use flate2::read::GzDecoder;
use oci_client::client::{Certificate, CertificateEncoding};
use pocker::{CLIError, LaunchOptions, canonicalize_clone, init_logging, launch_ptrace};
use pocker_sysaug::{PermsMode, RAW_SYSCALL_INFOS, SysAugArgs};
use std::io::Write;
use std::path::PathBuf;
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
            event!(Level::INFO, "Downloading image...");
            let (instance, layers) = download_image(image, name, download)?;

            event!(Level::INFO, "Creating instance...");
            std::fs::create_dir_all(&instance).context("Failed to create instance dir")?;
            let lockfile = instance.join(LOCKFILE_RUNNING);
            {
                let mut file =
                    std::fs::File::create(&lockfile).context("Failed to lock instance")?;
                writeln!(file, "")?;
            }

            event!(Level::INFO, "Running instance...");
            let cmd = cmd.unwrap_or("/bin/sh".to_string());
            let result = run_instance(cmd, &launch, instance, layers);

            event!(Level::INFO, "Cleaning up...");
            std::fs::remove_file(&lockfile).context("Failed to unlock instance")?;

            let retcode = result?;
            event!(Level::INFO, "Done.");
            std::process::exit(retcode.unwrap() as i32);
        }
    }
}

type InstanceAndLayers = (PathBuf, Vec<PathBuf>);

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
        ..Default::default()
    })
}

fn download_image(
    image_name: String,
    instance_name: Option<String>,
    args: ImageDownloadArgs,
) -> anyhow::Result<InstanceAndLayers> {
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

    std::fs::create_dir_all(&instances_dir)?;
    if instance_running.exists() {
        bail!(
            "Refusing to overwrite an existing, running instance: {}",
            &instance_name
        );
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

fn run_instance(
    cmd: String,
    args: &LaunchOptions,
    instance: PathBuf,
    layers: Vec<PathBuf>,
) -> anyhow::Result<Option<u8>> {
    let instance = instance.canonicalize()?;
    let args2 = SysAugArgs {
        chroot: Some(instance.clone()),
        rootfs: Some(instance),
        perms_mode: PermsMode::RootOnly,
        fail_fast: args.fail_fast,
        fix_sigsys: args.fix_sigsys,
        fix_mmap: args.fix_mmap || args.fix_attach,
        gdb: args.gdb,
        gdb_at: args.gdb_at,
        use_native_loader: args.use_native_loader,
    };

    match launch_ptrace(args2, &cmd, args.fix_attach) {
        Err(e) => bail!("Error: {:?}", e),
        Ok(ans) => Ok(ans),
    }
}
