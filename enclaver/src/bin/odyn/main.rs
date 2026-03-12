#![allow(clippy::new_without_default)]

pub mod api;
pub mod aux_api;
pub mod clock_sync;
pub mod config;
pub mod console;
pub mod egress;
pub mod enclave;
pub mod fs_mount;
pub mod helios_rpc;
pub mod ingress;
pub mod launcher;

use anyhow::{Result, anyhow};
use clap::Parser;
use log::{error, info};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use enclaver::constants::{APP_LOG_PORT, KMS_REGISTRY_HELIOS_PORT, STATUS_PORT};
use enclaver::nsm::Nsm;
use enclaver::runtime_vsock::RuntimeHostVsockPorts;

use api::ApiService;
use aux_api::AuxApiService;
use clock_sync::ClockSyncService;
use config::Configuration;
use console::{AppLog, AppStatus};
use egress::EgressService;
use fs_mount::HostFsMountService;
use helios_rpc::HeliosRpcService;
use ingress::IngressService;

#[derive(Parser)]
struct CliArgs {
    #[clap(long = "no-bootstrap", action)]
    no_bootstrap: bool,

    #[clap(long = "no-console", action)]
    no_console: bool,

    #[clap(long = "config-dir")]
    config_dir: String,

    #[clap(long = "work-dir")]
    work_dir: Option<PathBuf>,

    #[clap(required = true)]
    entrypoint: Vec<OsString>,

    #[clap(long = "verbose", short = 'v', action = clap::ArgAction::Count)]
    verbosity: u8,
}

#[derive(Default)]
struct StartedServices {
    hostfs_mounts: Option<HostFsMountService>,
    egress: Option<EgressService>,
    clock_sync: Option<ClockSyncService>,
    helios_rpc: Option<HeliosRpcService>,
    api: Option<ApiService>,
    aux_api: Option<AuxApiService>,
    ingress: Option<IngressService>,
}

impl StartedServices {
    async fn shutdown(mut self) {
        if let Some(ingress) = self.ingress.take() {
            info!("Stopping ingress");
            ingress.stop().await;
        }
        if let Some(aux_api) = self.aux_api.take() {
            info!("Stopping Aux API");
            aux_api.stop().await;
        }
        if let Some(api) = self.api.take() {
            info!("Stopping Internal API");
            api.stop().await;
        }
        if let Some(helios_rpc) = self.helios_rpc.take() {
            info!("Stopping Helios RPC");
            helios_rpc.stop().await;
        }
        if let Some(clock_sync) = self.clock_sync.take() {
            info!("Stopping clock sync");
            clock_sync.stop().await;
        }
        if let Some(egress) = self.egress.take() {
            info!("Stopping egress proxy");
            egress.stop().await;
        }
        if self.hostfs_mounts.take().is_some() {
            info!("Unmounting hostfs mounts");
        }
    }
}

async fn start_api_stack(
    config: &Configuration,
    nsm: Arc<Nsm>,
) -> Result<(ApiService, AuxApiService)> {
    let api = ApiService::start(config, nsm).await?;
    match AuxApiService::start(config).await {
        Ok(aux_api) => Ok((api, aux_api)),
        Err(err) => {
            api.stop().await;
            Err(err.context("failed to start Aux API after the Internal API was already running"))
        }
    }
}

fn install_egress_proxy_env_before_runtime(config: &Configuration) -> Result<()> {
    unsafe {
        // SAFETY: This runs in the synchronous startup path before the Tokio
        // runtime is created, so no worker threads or async tasks can observe
        // partially updated process-global environment variables.
        for (name, value) in config.egress_proxy_env_vars()? {
            std::env::set_var(name, value);
        }
    }
    Ok(())
}

fn log_launch_plan(
    config: &Configuration,
    args: &CliArgs,
    runtime_vsock: &RuntimeHostVsockPorts,
) -> Result<()> {
    info!(
        "Odyn launch plan: bootstrap={}, console={}, config_dir={}, work_dir={}, entrypoint={:?}",
        !args.no_bootstrap,
        !args.no_console,
        args.config_dir,
        args.work_dir
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<default>".to_string()),
        args.entrypoint
    );

    if let Some(proxy_uri) = config.egress_proxy_uri()? {
        info!(
            "Egress plan: enabled for user app environment via {} and host vsock port {}",
            proxy_uri, runtime_vsock.egress_port
        );
    } else {
        info!("Egress plan: disabled");
    }

    if let Some(api_port) = config.api_port() {
        let aux_api_port = config
            .aux_api_port()
            .ok_or_else(|| anyhow!("api.listen_port requires a valid Aux API port"))?;
        info!(
            "API plan: internal API on {}, Aux API on {} (required for attestation)",
            api_port, aux_api_port
        );
    } else {
        info!("API plan: disabled");
    }

    if config.listener_ports.is_empty() {
        info!("Ingress plan: disabled");
    } else {
        info!("Ingress plan: listener ports {:?}", config.listener_ports);
    }

    let helios_configs = config.helios_configs();
    if helios_configs.is_empty() {
        info!("Helios plan: disabled");
    } else {
        for helios in helios_configs {
            info!(
                "Helios plan: chain='{}' kind={:?} network={} local_rpc_port={}",
                helios.chain_name, helios.kind, helios.network, helios.listen_port
            );
        }
    }

    if let Some(clock_sync) = config.clock_sync_config() {
        info!(
            "Clock sync plan: enabled interval={}s host_vsock_port={}",
            clock_sync.interval_secs, runtime_vsock.clock_sync_port
        );
    } else {
        info!("Clock sync plan: disabled");
    }

    match config.manifest.hostfs_mounts() {
        Some(mounts) if !mounts.is_empty() => {
            for (index, mount) in mounts.iter().enumerate() {
                let port = runtime_vsock.hostfs_mount_port(index).map_err(|err| {
                    anyhow!(
                        "hostfs mount '{}' cannot be assigned a vsock port: {err}",
                        mount.name
                    )
                })?;
                info!(
                    "Hostfs plan: mount='{}' path={} required={} size_mb={} vsock_port={}",
                    mount.name,
                    mount.mount_path.display(),
                    mount.required,
                    mount.size_mb,
                    port
                );
            }
        }
        _ => info!("Hostfs plan: disabled"),
    }

    Ok(())
}

async fn launch(args: &CliArgs, config: Arc<Configuration>) -> Result<launcher::ExitStatus> {
    let nsm = Arc::new(Nsm::new());

    if !args.no_bootstrap {
        enclave::bootstrap(nsm.clone()).await?;
        info!("Enclave initialized");
    }

    let runtime_vsock = RuntimeHostVsockPorts::for_local_enclave()?;
    info!(
        "Odyn runtime detected local enclave CID={} host_runtime_ports{{egress={}, clock_sync={}}}",
        runtime_vsock.enclave_cid, runtime_vsock.egress_port, runtime_vsock.clock_sync_port
    );
    log_launch_plan(&config, args, &runtime_vsock)?;

    let mut services = StartedServices::default();
    let launch_result = async {
        services.hostfs_mounts = Some(HostFsMountService::start(&config, &runtime_vsock).await?);
        services.egress = Some(EgressService::start(&config, &runtime_vsock).await?);

        // Start clock sync service. It is enabled by default unless disabled in the manifest.
        services.clock_sync = Some(ClockSyncService::start(&config, &runtime_vsock));

        // Start Helios in background (non-blocking, app starts immediately)
        services.helios_rpc = Some(HeliosRpcService::start(&config).await?);
        if config
            .kms_integration_config()
            .map(|kms| kms.registry_discovery_configured())
            .unwrap_or(false)
        {
            info!("Waiting for Helios auth-chain RPC readiness required by Nova KMS");
            let helios_rpc = services.helios_rpc.as_mut().ok_or_else(|| {
                anyhow!("invariant violated: Helios service missing after successful start")
            })?;
            if !helios_rpc
                .wait_ready_for_port(KMS_REGISTRY_HELIOS_PORT)
                .await
            {
                return Err(anyhow!(
                    "Helios auth-chain RPC failed to become ready on local port {}",
                    KMS_REGISTRY_HELIOS_PORT
                ));
            }
        }

        let (api, aux_api) = start_api_stack(&config, nsm.clone()).await?;
        services.api = Some(api);
        services.aux_api = Some(aux_api);

        // Start ingress last, once all local services are bound and ready.
        services.ingress = Some(IngressService::start(&config)?);

        let creds = launcher::Credentials { uid: 0, gid: 0 };
        info!("Starting {:?}", args.entrypoint);
        let exit_status =
            launcher::start_child(args.entrypoint.clone(), creds, args.work_dir.clone()).await??;
        info!("Entrypoint {}", exit_status);

        Ok(exit_status)
    }
    .await;

    services.shutdown().await;
    launch_result
}

async fn run(args: &CliArgs, config: Arc<Configuration>) -> Result<()> {
    // Start the status and logs listeners ASAP so that if we fail to
    // initialize, we can communicate the status and stream the logs
    let app_status = AppStatus::new();
    let app_status_task = app_status.start_serving(STATUS_PORT);

    let mut console_task = None;
    if !args.no_console {
        let app_log = AppLog::with_stdio_redirect()?;
        console_task = Some(app_log.start_serving(APP_LOG_PORT));
    }

    match launch(args, config).await {
        Ok(exit_status) => app_status.exited(exit_status),
        Err(err) => app_status.fatal(format_fatal_error(&err)),
    };

    app_status_task.await??;

    if let Some(task) = console_task {
        task.abort();
        _ = task.await;
    }

    Ok(())
}

fn main() {
    let args = CliArgs::parse();
    enclaver::utils::init_logging(args.verbosity);

    let config = match Configuration::load_blocking(&args.config_dir) {
        Ok(config) => config,
        Err(err) => {
            error!("Error: {err:#}");
            std::process::exit(1);
        }
    };
    if let Err(err) = install_egress_proxy_env_before_runtime(&config) {
        error!("Error: {err:#}");
        std::process::exit(1);
    }

    #[cfg(feature = "tracing")]
    console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .server_addr(([0, 0, 0, 0], 51000))
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime");

    if let Err(err) = runtime.block_on(run(&args, Arc::new(config))) {
        error!("Error: {err:#}");
        std::process::exit(1);
    }
}

fn format_fatal_error(err: &anyhow::Error) -> String {
    format!("{err:#}")
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::{format_fatal_error, start_api_stack};
    use anyhow::anyhow;
    use enclaver::manifest::{Api, AuxApi, Manifest, Sources};
    use enclaver::nsm::Nsm;

    use crate::config::Configuration;

    fn test_configuration(api_port: u16, aux_api_port: u16) -> Configuration {
        Configuration {
            config_dir: PathBuf::from("."),
            manifest: Manifest {
                version: "v1".to_string(),
                name: "test".to_string(),
                target: "target:latest".to_string(),
                sources: Sources {
                    app: "app:latest".to_string(),
                    odyn: None,
                    sleeve: None,
                },
                signature: None,
                ingress: None,
                egress: None,
                defaults: None,
                api: Some(Api {
                    listen_port: api_port,
                }),
                aux_api: Some(AuxApi {
                    listen_port: Some(aux_api_port),
                }),
                storage: None,
                kms_integration: None,
                helios_rpc: None,
                clock_sync: None,
            },
            listener_ports: Vec::new(),
        }
    }

    #[test]
    fn fatal_error_includes_full_context_chain() {
        let err = anyhow!("inner hostfs error").context("failed to mount hostfs 'appdata'");

        let formatted = format_fatal_error(&err);

        assert!(formatted.contains("failed to mount hostfs 'appdata'"));
        assert!(formatted.contains("inner hostfs error"));
    }

    #[tokio::test]
    async fn start_api_stack_rolls_back_api_when_aux_api_fails() {
        let api_probe = TcpListener::bind(("127.0.0.1", 0)).expect("reserve api port");
        let api_port = api_probe.local_addr().expect("api addr").port();
        drop(api_probe);

        let aux_conflict = TcpListener::bind(("127.0.0.1", 0)).expect("reserve aux api port");
        let aux_api_port = aux_conflict.local_addr().expect("aux addr").port();

        let config = test_configuration(api_port, aux_api_port);
        let err = match start_api_stack(&config, Arc::new(Nsm::new())).await {
            Ok(_) => panic!("aux api bind should fail while its port is occupied"),
            Err(err) => err,
        };
        assert!(!err.to_string().is_empty());

        TcpListener::bind(("127.0.0.1", api_port))
            .expect("api port should be released when aux api startup fails");
    }
}
