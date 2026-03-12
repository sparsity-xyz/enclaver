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

use enclaver::constants::{APP_LOG_PORT, CLOCK_SYNC_PORT, HTTP_EGRESS_VSOCK_PORT, STATUS_PORT};
use enclaver::hostfs::hostfs_vsock_port;
use enclaver::nsm::Nsm;

use api::ApiService;
use aux_api::AuxApiService;
use clock_sync::ClockSyncService;
use config::Configuration;
use console::{AppLog, AppStatus};
use egress::EgressService;
use fs_mount::HostFsMountService;
use helios_rpc::HeliosRpcService;
use ingress::IngressService;

const KMS_AUTH_CHAIN_HELIOS_PORT: u16 = 18545;

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

fn log_launch_plan(config: &Configuration, args: &CliArgs) -> Result<()> {
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

    if let Some(proxy_uri) = config.egress_proxy_uri() {
        info!(
            "Egress plan: enabled for user app environment via {} and host vsock port {}",
            proxy_uri, HTTP_EGRESS_VSOCK_PORT
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
            "Clock sync plan: enabled interval={}s host_vsock_port={CLOCK_SYNC_PORT}",
            clock_sync.interval_secs
        );
    } else {
        info!("Clock sync plan: disabled");
    }

    match config.manifest.hostfs_mounts() {
        Some(mounts) if !mounts.is_empty() => {
            for (index, mount) in mounts.iter().enumerate() {
                let port = hostfs_vsock_port(index).map_err(|err| {
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

async fn launch(args: &CliArgs) -> Result<launcher::ExitStatus> {
    let config = Arc::new(Configuration::load(&args.config_dir).await?);
    log_launch_plan(&config, args)?;

    let nsm = Arc::new(Nsm::new());

    if !args.no_bootstrap {
        enclave::bootstrap(nsm.clone()).await?;
        info!("Enclave initialized");
    }

    let mut services = StartedServices::default();
    let launch_result = async {
        services.hostfs_mounts = Some(HostFsMountService::start(&config).await?);
        services.egress = Some(EgressService::start(&config).await?);

        // Start clock sync service. It is enabled by default unless disabled in the manifest.
        services.clock_sync = Some(ClockSyncService::start(&config));

        // Start Helios in background (non-blocking, app starts immediately)
        services.helios_rpc = Some(HeliosRpcService::start(&config).await?);
        if config
            .kms_integration_config()
            .map(|kms| kms.registry_discovery_configured())
            .unwrap_or(false)
        {
            info!("Waiting for Helios auth-chain RPC readiness required by Nova KMS");
            if !services
                .helios_rpc
                .as_mut()
                .expect("helios service just started")
                .wait_ready_for_port(KMS_AUTH_CHAIN_HELIOS_PORT)
                .await
            {
                return Err(anyhow!(
                    "Helios auth-chain RPC failed to become ready on local port {}",
                    KMS_AUTH_CHAIN_HELIOS_PORT
                ));
            }
        }

        let (api, aux_api) = tokio::try_join!(
            ApiService::start(&config, nsm.clone()),
            AuxApiService::start(&config),
        )?;
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

async fn run(args: &CliArgs) -> Result<()> {
    // Start the status and logs listeners ASAP so that if we fail to
    // initialize, we can communicate the status and stream the logs
    let app_status = AppStatus::new();
    let app_status_task = app_status.start_serving(STATUS_PORT);

    let mut console_task = None;
    if !args.no_console {
        let app_log = AppLog::with_stdio_redirect()?;
        console_task = Some(app_log.start_serving(APP_LOG_PORT));
    }

    match launch(args).await {
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

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();
    enclaver::utils::init_logging(args.verbosity);

    #[cfg(feature = "tracing")]
    console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .server_addr(([0, 0, 0, 0], 51000))
        .init();

    if let Err(err) = run(&args).await {
        error!("Error: {err:#}");
        std::process::exit(1);
    }
}

fn format_fatal_error(err: &anyhow::Error) -> String {
    format!("{err:#}")
}

#[cfg(test)]
mod tests {
    use super::format_fatal_error;
    use anyhow::anyhow;

    #[test]
    fn fatal_error_includes_full_context_chain() {
        let err = anyhow!("inner hostfs error").context("failed to mount hostfs 'appdata'");

        let formatted = format_fatal_error(&err);

        assert!(formatted.contains("failed to mount hostfs 'appdata'"));
        assert!(formatted.contains("inner hostfs error"));
    }
}
