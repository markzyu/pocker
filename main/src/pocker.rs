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
    manifest::{ImageIndexEntry, OciImageManifest},
};
use oci_spec::image::{Arch, Os};
use pocker::{LaunchOptions, init_logging, launch_ptrace};
use pocker_ptrace::setup_shared_memory;
use pocker_sysaug::{MountConfig, PermsMode, SysAugArgs, SysAugConfig, get_metadata_dir};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use tracing::{Level, event};
use webpki_root_certs::TLS_SERVER_ROOT_CERTS;

const LOCKFILE_RUNNING: &str = ".pocker-running";
const SUPPORTED_LAYER_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];

#[derive(Parser, Debug)]
#[command(version = "0.3.0", author = "Zhongzhi Yu")]
struct CLIArgs {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Clone, Debug, Subcommand)]
enum Commands {
    /// Download a container from image name, and unarchive with fake permissions in mind
    Pull {
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
    /// Download and run a container from image name
    /// (This is a hidden command for now, because overlay fs is not ready)
    #[command(hide = true)]
    Run {
        /// The name of the container image
        image: String,

        /// An optional command to run. This defaults to /bin/sh, for now, not the one specified in the image.
        #[arg(long)]
        cmd: Option<Vec<String>>,

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

    #[arg(long)]
    redownload: bool,
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
            let storage_dir = get_storage_dir(&download)?;
            let layers = download_image(image.clone(), &launch, &download)?;
            let layers = launch_ptrace_to_untar_layers(
                image.clone(),
                layers,
                &launch,
                &download,
                shared_fd.as_raw_fd(),
                mmap_addr,
            )?;

            event!(Level::INFO, "Creating instance...");
            let instances_dir = storage_dir.join("instances");
            let instance_name = name.unwrap_or(image.clone());
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

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all() // Enables both the I/O driver and the time driver
                .build()?;
            let reference_str = image_name_to_reference_str(&download, &image);
            let (_, config) = fetch_manifest_and_config_cached(&rt, &download, &reference_str)?;
            let cmd = cmd.unwrap_or(config.cmd.clone());
            event!(Level::INFO, "Running command: {:?}", &cmd);

            let result = run_instance(
                cmd,
                &launch,
                instance,
                layers,
                config,
                shared_fd.as_raw_fd(),
                mmap_addr,
            );

            event!(Level::INFO, "Cleaning up...");
            std::fs::remove_file(&lockfile).context("Failed to unlock instance")?;

            let retcode = result?;
            event!(Level::INFO, "Done.");
            std::process::exit(retcode.unwrap() as i32);
        }
        Commands::Pull {
            image,
            internal_layer,
            launch,
            download,
        } => {
            if let Some(layer) = internal_layer {
                event!(Level::INFO, "Downloading layer {}...", &layer);
                untar_layer_from_tracee(layer, &download)?;
            } else {
                let (shared_fd, mmap_addr) = setup_shared_memory().context("Preparing ptrace")?;
                let layers = download_image(image.clone(), &launch, &download)?;
                launch_ptrace_to_untar_layers(
                    image,
                    layers,
                    &launch,
                    &download,
                    shared_fd.as_raw_fd(),
                    mmap_addr,
                )?;
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

fn untar_layer_from_tracee(layer: String, download: &ImageDownloadArgs) -> anyhow::Result<()> {
    let storage_dir = get_storage_dir(&download)?;
    let layers_dir = storage_dir.join("layers");
    let cache_dir = storage_dir.join("cache");
    let tar_name = format!("{}.tar.gz", layer);
    let tar_path = cache_dir.join(tar_name);
    let layer_dir = layers_dir.join(&layer);

    let tar_file = std::fs::File::open(tar_path)?;
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

fn get_cache_path(
    args: &ImageDownloadArgs,
    reference_str: &String,
) -> anyhow::Result<(PathBuf, String)> {
    let storage_dir = get_storage_dir(args)?;
    let layers_dir = storage_dir.join("layers");
    let cache_dir = storage_dir.join("cache");
    std::fs::create_dir_all(&layers_dir).context("Creating pocker download cache")?;
    std::fs::create_dir_all(&cache_dir).context("Creating pocker download cache")?;

    let cache_name = reference_str
        .strip_prefix(&args.registry_host)
        .unwrap()
        .replace("_", "__")
        .replace("/", "_");
    Ok((cache_dir, cache_name))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OciConfig {
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    cmd: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    working_dir: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciConfigRoot {
    config: OciConfig,
}

fn image_name_to_reference_str(args: &ImageDownloadArgs, image_name: &String) -> String {
    if image_name.contains('/') {
        format!("{}/{}", args.registry_host, &image_name)
    } else {
        format!(
            "{}/{}/{}",
            args.registry_host, args.registry_namespace, &image_name
        )
    }
}

fn fetch_manifest_and_config_cached(
    rt: &tokio::runtime::Runtime,
    args: &ImageDownloadArgs,
    reference_str: &String,
) -> anyhow::Result<(OciImageManifest, OciConfig)> {
    let (cache_dir, cache_name) = get_cache_path(args, reference_str)?;
    let manifest_path = cache_dir.join(format!("{}.manifest.json", cache_name));
    let config_path = cache_dir.join(format!("{}.config.json", cache_name));

    if manifest_path.exists() && config_path.exists() {
        let err = "Failed to read manifest or config from cache";
        let manifest_str = std::fs::read_to_string(&manifest_path).context(err)?;
        let config_str = std::fs::read_to_string(&config_path).context(err)?;
        let manifest: OciImageManifest = serde_json::from_str(&manifest_str).context(err)?;
        let config: OciConfigRoot = serde_json::from_str(&config_str).context(err)?;
        return Ok((manifest, config.config));
    }

    let client = get_oci_client();
    let reference: oci_client::Reference = reference_str.parse()?;
    let auth = oci_client::secrets::RegistryAuth::Anonymous;
    let (image, _, config) = rt.block_on(client.pull_manifest_and_config(&reference, &auth))?;
    save_manifest_and_config(args, &image, &config, &reference_str)?;

    let config: OciConfigRoot = serde_json::from_str(&config)?;
    Ok((image, config.config))
}

fn save_manifest_and_config<C>(
    args: &ImageDownloadArgs,
    image: &OciImageManifest,
    config: C,
    reference_str: &String,
) -> anyhow::Result<()>
where
    C: AsRef<[u8]>,
{
    let (cache_dir, cache_name) = get_cache_path(args, reference_str)?;
    let manifest_str = serde_json::to_string(&image).context("Saving image manifest")?;
    let manifest_name = format!("{}.manifest.json", cache_name);
    let manifest_path = cache_dir.join(manifest_name);
    std::fs::write(&manifest_path, manifest_str).context("Saving image manifest")?;

    // let config_str = serde_json::to_string(&config).context("Saving image config")?;
    let config_name = format!("{}.config.json", cache_name);
    let config_path = cache_dir.join(config_name);
    std::fs::write(&config_path, &config).context("Saving image config")?;
    Ok(())
}

/// Downloads only the tar files, if they don't exist already.
/// Returns a list of layer ids
fn download_image(
    image_name: String,
    _launch: &LaunchOptions,
    args: &ImageDownloadArgs,
) -> anyhow::Result<Vec<String>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all() // Enables both the I/O driver and the time driver
        .build()?;

    // 2. Execute the future, blocking the current thread until completion
    let reference_str = image_name_to_reference_str(args, &image_name);

    let (cache_dir, cache_name) = get_cache_path(args, &reference_str)?;
    let cache_path = cache_dir.join(&cache_name);
    if cache_path.exists() {
        let err_ctx = "Checking cached image digests";
        let mut file = std::fs::File::open(&cache_path).context(err_ctx)?;
        let mut cached_image = String::new();
        file.read_to_string(&mut cached_image).context(err_ctx)?;
        let hashes: Vec<_> = cached_image.trim().split(",").collect();

        let (image, _) = fetch_manifest_and_config_cached(&rt, args, &reference_str)?;

        if hashes.len() > 0 && hashes.len() == image.layers.len() {
            let actual: Vec<_> = hashes.iter().map(|x| x.to_string()).collect();
            let expected: Vec<_> = image.layers.iter().map(|x| x.digest.clone()).collect();

            if actual == expected && !args.redownload {
                // TODO: actually check hashes of tar files
                return Ok(actual);
            }

            event!(
                Level::DEBUG,
                "Redownloading layers, because {:?} != {:?}",
                actual,
                expected
            );
        }
    }

    event!(Level::INFO, "Downloading image...");
    let image: anyhow::Result<_> = rt.block_on(async {
        let client = get_oci_client();
        let reference: oci_client::Reference = reference_str.parse()?;
        let auth = oci_client::secrets::RegistryAuth::Anonymous;
        let image = client
            .pull(&reference, &auth, SUPPORTED_LAYER_TYPES.to_vec())
            .await?;
        Ok(image)
    });
    let image = image?;
    let manifest = image.manifest.expect("No manifest found in image");
    save_manifest_and_config(args, &manifest, &image.config.data, &reference_str)?;

    let mut hashes: Vec<String> = Vec::new();
    for layer in image.layers {
        let digest = layer.sha256_digest();
        hashes.push(digest.clone());

        if !SUPPORTED_LAYER_TYPES.contains(&layer.media_type.as_str()) {
            bail!("Unknown image format: {}", &layer.media_type);
        }

        let tar_name = format!("{}.tar.gz", &digest);
        let tar_path = cache_dir.join(&tar_name);
        std::fs::write(&tar_path, layer.data).context("Saving layer tarfile")?;
    }

    let all_hashes = hashes.join(",");
    let err_ctx = format!("Saving cached image digests: {:?}", &cache_path);
    let mut file = std::fs::File::create(&cache_path).context(err_ctx.clone())?;
    writeln!(file, "{}", all_hashes).context(err_ctx)?;

    Ok(hashes)
}

fn launch_ptrace_to_untar_layers(
    image_name: String,
    layers: Vec<String>,
    launch: &LaunchOptions,
    args: &ImageDownloadArgs,
    shared_fd: RawFd,
    mmap_addr: usize,
) -> anyhow::Result<Vec<PathBuf>> {
    let storage_dir = get_storage_dir(&args)?;
    let layers_dir = storage_dir.join("layers");

    std::fs::create_dir_all(&layers_dir).context("Creating pocker download cache")?;

    let mut layer_dirs: Vec<PathBuf> = Vec::new();
    for digest in layers {
        let layer_dir = layers_dir.join(&digest);
        layer_dirs.push(layer_dir.clone());

        if layer_dir.is_dir() {
            if !args.redownload {
                event!(Level::INFO, "Skipping untar of layer {}", &digest);
                continue;
            } else {
                std::fs::remove_dir_all(&layer_dir)
                    .context(format!("Redownloading layer {}", &digest))?;
            }
        }

        std::fs::create_dir_all(&layer_dir).context("Creating untarred layer dir")?;

        event!(Level::INFO, "Starting to untar layer {}", &digest);
        let self_path = std::env::current_exe()?.canonicalize()?;
        let args2 = SysAugArgs {
            chroot: None,
            rootfs: Some(layer_dir.clone()),
            workdir: None,
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
        new_args.push("pull".into());
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
    cmd: Vec<String>,
    args: &LaunchOptions,
    instance_path: PathBuf,
    layers: Vec<PathBuf>,
    image_config: OciConfig,
    shared_fd: RawFd,
    mmap_addr: usize,
) -> anyhow::Result<Option<u8>> {
    let rootfs = instance_path.canonicalize()?;
    let args2 = SysAugArgs {
        chroot: Some(rootfs.clone()),
        rootfs: Some(rootfs.clone()),
        workdir: image_config.working_dir.map(Into::into),
        perms_mode: PermsMode::RootOnly,
        fail_fast: args.fail_fast,
        fix_sigsys: args.fix_sigsys,
        fix_mmap: args.fix_mmap || args.fix_attach,
        no_seccomp: args.no_seccomp,
        gdb: args.gdb,
        gdb_at: args.gdb_at,
        use_native_loader: false,
    };

    let err1 = "Cannot convert layer storage path to utf8";
    let mut config = SysAugConfig::default();
    config.mounts = layers
        .iter()
        .map(|path| MountConfig {
            source: path.to_str().expect(err1).to_string(),
            target: "/".to_string(),
            fstype: "overlay".to_string(),
        })
        .collect();

    let config_str = serde_json::to_string(&config).context("Creating pocker runtime config")?;
    let metadata_dir = get_metadata_dir(Some(&rootfs)).expect("Invalid rootfs path");
    let config_path = metadata_dir.join("config.json");
    std::fs::create_dir_all(&metadata_dir).context("Creating pocker runtime metadata dir")?;
    std::fs::write(&config_path, config_str).context("Writing pocker runtime config")?;

    event!(
        Level::WARN,
        "Beware! This command is still in early development!"
    );
    event!(
        Level::WARN,
        "Pocker will overwrite a layer to start the container!"
    );

    // Clear all environment variables. Set new ENV according to image config
    unsafe {
        let keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
        for key in keys {
            std::env::remove_var(key);
        }

        // Provide a few defaults
        std::env::set_var("LD_PRELOAD", "");
        std::env::set_var("PATH", "/bin:/sbin:/usr/bin:/usr/sbin");

        for env_str in image_config.env {
            if let Some(idx) = env_str.find('=')
                && idx < env_str.len()
            {
                let key = &env_str[..idx];
                let val = &env_str[idx + 1..];
                std::env::set_var(key, val);
            }
        }
    }

    let mut child = std::process::Command::new(&cmd[0]);
    child.args(&cmd[1..]);
    match launch_ptrace(args2, child, args.fix_attach, shared_fd, mmap_addr) {
        Err(e) => bail!("Error: {:?}", e),
        Ok(ans) => Ok(ans),
    }
}
