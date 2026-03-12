use crate::constants::{
    APP_LOG_PORT, EIF_FILE_NAME, MANIFEST_FILE_NAME, RELEASE_BUNDLE_DIR, STATUS_PORT,
};
use crate::hostfs::{CONTAINER_HOSTFS_ROOT, hostfs_vsock_port};
use crate::manifest::{Defaults, Manifest, load_manifest};
use crate::runtime_vsock::{RuntimeHostVsockPorts, allocate_managed_enclave_cid};
use crate::utils;
use anyhow::{Result, anyhow};
use futures_util::stream::StreamExt;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use tokio_util::sync::CancellationToken;
use tokio_vsock::VsockStream;

use crate::nitro_cli::{EnclaveInfo, NitroCLI, RunEnclaveArgs};
use crate::proxy::egress_http::HostHttpProxy;
use crate::proxy::fs_host::HostFsProxy;
use crate::proxy::ingress::HostProxy;
use std::collections::HashSet;

const LOG_VSOCK_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const STATUS_VSOCK_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const STATUS_VSOCK_RETRY_LIMIT: i32 = 100;
const CLOCK_SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CLOCK_SYNC_MAX_REQUEST_LEN: usize = 16;

const DEFAULT_CPU_COUNT: i32 = 2;
const DEFAULT_MEMORY_MB: i32 = 4096;
const HOST_RUNTIME_BIND_RETRY_LIMIT: usize = 16;
const MANAGED_CID_CONFLICT_RETRY_LIMIT: usize = 8;

pub struct EnclaveOpts {
    pub eif_path: Option<PathBuf>,
    pub manifest_path: Option<PathBuf>,
    pub cpu_count: Option<i32>,
    pub memory_mb: Option<i32>,
    pub debug_mode: bool,
}

pub struct Enclave {
    cli: NitroCLI,
    eif_path: PathBuf,
    manifest: Manifest,
    cpu_count: i32,
    memory_mb: i32,
    debug_mode: bool,
    enclave_info: Option<EnclaveInfo>,
    runtime_vsock: Option<RuntimeHostVsockPorts>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Enclave {
    pub async fn new(opts: EnclaveOpts) -> Result<Self> {
        let eif_path = match opts.eif_path {
            Some(eif_path) => eif_path,
            None => PathBuf::from(RELEASE_BUNDLE_DIR).join(EIF_FILE_NAME),
        };

        // Test that the EIF exists
        let _ = File::open(&eif_path)
            .await
            .map_err(|e| anyhow!("failed to open EIF file at {}: {e}", eif_path.display()))?;

        let manifest_path = match opts.manifest_path {
            Some(manifest_path) => manifest_path,
            None => PathBuf::from(RELEASE_BUNDLE_DIR).join(MANIFEST_FILE_NAME),
        };

        let manifest = load_manifest(&manifest_path).await?;

        let cpu_count = match (opts.cpu_count, &manifest.defaults) {
            (Some(cpu_count), _) => cpu_count,
            (
                None,
                Some(Defaults {
                    cpu_count: Some(cpu_count),
                    ..
                }),
            ) => {
                debug!("using cpu_count = {cpu_count} based on defaults from manifest");
                *cpu_count
            }
            _ => {
                debug!("no cpu_count specified, defaulting to {DEFAULT_CPU_COUNT}");
                DEFAULT_CPU_COUNT
            }
        };

        let memory_mb = match (opts.memory_mb, &manifest.defaults) {
            (Some(memory_mb), _) => memory_mb,
            (
                None,
                Some(Defaults {
                    memory_mb: Some(memory_mb),
                    ..
                }),
            ) => {
                debug!("using memory_mb = {memory_mb} based on defaults from manifest");
                *memory_mb
            }
            _ => {
                debug!("no memory_mb specified, defaulting to {DEFAULT_MEMORY_MB}");
                DEFAULT_MEMORY_MB
            }
        };

        debug!(
            "using fixed enclave-local vsock ports: status={STATUS_PORT}, app_log={APP_LOG_PORT}; host-side runtime ports will be derived from the managed enclave CID"
        );

        Ok(Self {
            cli: NitroCLI::new(),
            eif_path: eif_path.to_path_buf(),
            manifest,
            cpu_count,
            memory_mb,
            debug_mode: opts.debug_mode,
            enclave_info: None,
            runtime_vsock: None,
            tasks: Vec::new(),
        })
    }

    // Start the enclave and run it until it either exits or is interrupted via
    // the passed in cancellation token. Terminates the enclave prior to returning.
    pub async fn run(mut self, cancellation: CancellationToken) -> Result<EnclaveExitStatus> {
        if self.enclave_info.is_some() {
            return Err(anyhow!("Enclave already started"));
        }

        let mut conflict_rejected_cids = HashSet::new();
        let enclave_info = loop {
            ensure_managed_cid_retry_budget(&conflict_rejected_cids)?;

            let runtime_vsock = self.prepare_host_runtime(&conflict_rejected_cids).await?;
            self.runtime_vsock = Some(runtime_vsock.clone());

            info!(
                "starting enclave with managed CID={} host_runtime_ports{{egress={}, clock_sync={}}}",
                runtime_vsock.enclave_cid, runtime_vsock.egress_port, runtime_vsock.clock_sync_port
            );
            match self
                .cli
                .run_enclave(RunEnclaveArgs {
                    cpu_count: self.cpu_count,
                    memory_mb: self.memory_mb,
                    eif_path: self.eif_path.clone(),
                    cid: Some(runtime_vsock.enclave_cid),
                    debug_mode: self.debug_mode,
                })
                .await
            {
                Ok(info) => break info,
                Err(err) if is_managed_cid_conflict_error(&err) => {
                    warn!(
                        "managed CID {} was claimed before nitro-cli run-enclave completed: {err:#}; retrying with a different CID",
                        runtime_vsock.enclave_cid
                    );
                    conflict_rejected_cids.insert(runtime_vsock.enclave_cid);
                    if let Err(cleanup_err) = self.cleanup_running_state().await {
                        return Err(cleanup_err.context(format!(
                            "failed to clean up after managed CID {} start collision",
                            runtime_vsock.enclave_cid
                        )));
                    }
                }
                Err(err) => {
                    if let Err(cleanup_err) = self.cleanup_running_state().await {
                        error!("error cleaning up after failed enclave start: {cleanup_err}");
                    }
                    return Err(err.context(format!(
                        "failed to start enclave with managed CID {}",
                        runtime_vsock.enclave_cid
                    )));
                }
            }
        };

        self.enclave_info = Some(enclave_info.clone());

        info!(
            "started enclave ID={}, CID={}",
            enclave_info.id, enclave_info.cid
        );

        if self.debug_mode {
            // TODO: Should we let an an EOF from the console terminate run?
            self.attach_debug_console(&enclave_info.id).await?;
        }

        self.start_odyn_log_stream(enclave_info.cid)?;

        self.start_ingress_proxies(enclave_info.cid).await?;

        let exit_res = tokio::select! {
            exit_res = Enclave::await_exit(enclave_info.cid, STATUS_PORT) =>
                exit_res,

            _ = cancellation.cancelled() =>
                Ok(EnclaveExitStatus::Cancelled),
        };

        if let Err(err) = self.cleanup_running_state().await {
            error!("error terminating enclave: {err}");
        }

        match exit_res {
            Ok(EnclaveExitStatus::Exited(code)) => info!("enclave exited with code {code}"),
            Ok(EnclaveExitStatus::Signaled(signal)) => {
                info!("enclave stopped due to signal {signal}")
            }
            Ok(EnclaveExitStatus::Fatal(ref error)) => {
                info!("enclave exited due to fatal error: {error}")
            }
            Ok(EnclaveExitStatus::Cancelled) => (),
            Err(ref err) => error!("error waiting for enclave exit: {err}"),
        };

        exit_res
    }

    async fn prepare_host_runtime(
        &mut self,
        conflict_rejected_cids: &HashSet<u32>,
    ) -> Result<RuntimeHostVsockPorts> {
        let mut bind_unavailable_cids = conflict_rejected_cids.clone();
        for attempt in 1..=HOST_RUNTIME_BIND_RETRY_LIMIT {
            let runtime_vsock = self
                .select_runtime_vsock_ports(&bind_unavailable_cids)
                .await?;

            debug!(
                "attempting host runtime reservation with managed CID={} egress_port={} clock_sync_port={} (attempt {}/{})",
                runtime_vsock.enclave_cid,
                runtime_vsock.egress_port,
                runtime_vsock.clock_sync_port,
                attempt,
                HOST_RUNTIME_BIND_RETRY_LIMIT
            );

            let start_result = async {
                // Start host-side services before the enclave so they are ready
                // when Odyn begins dialing host VSOCK endpoints.
                self.start_egress_proxy(&runtime_vsock).await?;
                self.start_hostfs_proxies(&runtime_vsock)?;
                self.start_clock_sync_server(&runtime_vsock)?;
                Ok(())
            }
            .await;

            match start_result {
                Ok(()) => return Ok(runtime_vsock),
                Err(err) if is_addr_in_use_error(&err) => {
                    bind_unavailable_cids.insert(runtime_vsock.enclave_cid);
                    warn!(
                        "managed CID {} collided on a derived host runtime VSOCK port (attempt {}/{}): {err:#}; retrying with a different managed CID",
                        runtime_vsock.enclave_cid, attempt, HOST_RUNTIME_BIND_RETRY_LIMIT
                    );
                    self.abort_tasks().await;
                    continue;
                }
                Err(err) => {
                    self.abort_tasks().await;
                    return Err(err);
                }
            }
        }

        Err(anyhow!(
            "failed to reserve host-side runtime VSOCK ports after {} attempts",
            HOST_RUNTIME_BIND_RETRY_LIMIT
        ))
    }

    async fn select_runtime_vsock_ports(
        &self,
        excluded_cids: &HashSet<u32>,
    ) -> Result<RuntimeHostVsockPorts> {
        let mut used_cids = self
            .cli
            .describe_enclaves()
            .await?
            .into_iter()
            .map(|enclave| enclave.cid)
            .collect::<HashSet<_>>();
        used_cids.extend(excluded_cids.iter().copied());
        let cid = allocate_managed_enclave_cid(&used_cids)?;
        RuntimeHostVsockPorts::for_cid(cid)
    }

    async fn start_ingress_proxies(&mut self, cid: u32) -> Result<()> {
        let ingress = match &self.manifest.ingress {
            Some(ingress) => ingress,
            None => {
                info!("no ingress defined, no ingress proxies will be started");
                return Ok(());
            }
        };

        for item in ingress {
            let listen_port = item.listen_port;
            info!("starting ingress proxy on port {listen_port}");
            let proxy = HostProxy::bind(listen_port).await?;
            self.tasks.push(utils::spawn!("ingress proxy", async move {
                proxy.serve(cid, listen_port.into()).await;
            })?)
        }

        Ok(())
    }

    async fn start_egress_proxy(&mut self, runtime_vsock: &RuntimeHostVsockPorts) -> Result<()> {
        // Note: we _could_ start the egress proxy no matter what, but there is no sense in it,
        // and skipping it seems (barely) safer - so we may as well.
        if !self.manifest.egress_proxy_enabled() {
            info!("no egress defined, no egress proxy will be started");
            return Ok(());
        }

        let proxy = HostHttpProxy::bind(runtime_vsock.egress_port).map_err(|err| {
            annotate_host_vsock_bind_error(
                err,
                format!(
                    "host egress proxy vsock port {} for managed CID {}",
                    runtime_vsock.egress_port, runtime_vsock.enclave_cid
                ),
            )
        })?;
        info!(
            "egress proxy bound to host-side vsock port {} for managed CID {}",
            runtime_vsock.egress_port, runtime_vsock.enclave_cid
        );
        self.tasks.push(utils::spawn!("egress proxy", async move {
            proxy.serve().await;
        })?);

        Ok(())
    }

    fn start_hostfs_proxies(&mut self, runtime_vsock: &RuntimeHostVsockPorts) -> Result<()> {
        let Some(mounts) = self.manifest.hostfs_mounts() else {
            info!("no hostfs mounts defined, no hostfs proxies will be started");
            return Ok(());
        };

        // Mount order in the manifest defines the hostfs offset within the
        // per-enclave runtime VSOCK block. Odyn derives the same host-side
        // port from its local CID, so both sides must walk the list in the
        // same order.
        for (index, mount) in mounts.iter().enumerate() {
            let port = hostfs_vsock_port(runtime_vsock.enclave_cid, index).map_err(|err| {
                anyhow!(
                    "hostfs mount '{}' cannot be assigned a vsock port: {err}",
                    mount.name
                )
            })?;

            let root = PathBuf::from(CONTAINER_HOSTFS_ROOT).join(&mount.name);
            if !root.exists() {
                if mount.required {
                    return Err(anyhow!(
                        "required hostfs mount '{}' is missing its runtime bind at {}",
                        mount.name,
                        root.display()
                    ));
                }

                info!(
                    "optional hostfs mount '{}' is not bound at {}, skipping proxy startup",
                    mount.name,
                    root.display()
                );
                continue;
            }

            let proxy = HostFsProxy::bind(&mount.name, root, false, port).map_err(|err| {
                annotate_host_vsock_bind_error(
                    err,
                    format!(
                        "hostfs mount '{}' host-side vsock port {} for managed CID {}",
                        mount.name, port, runtime_vsock.enclave_cid
                    ),
                )
            })?;

            info!(
                "starting hostfs proxy for mount '{}' on host-side vsock port {} (managed CID {})",
                mount.name, port, runtime_vsock.enclave_cid
            );
            self.tasks.push(utils::spawn!(
                &format!("hostfs proxy ({})", mount.name),
                async move {
                    proxy.serve().await;
                }
            )?);
        }

        Ok(())
    }

    fn start_clock_sync_server(&mut self, runtime_vsock: &RuntimeHostVsockPorts) -> Result<()> {
        let clock_sync = self.manifest.effective_clock_sync();

        if !clock_sync.enabled {
            info!("clock sync disabled in manifest, skipping host time server");
            return Ok(());
        }

        info!(
            "starting host-side clock sync time server on vsock port {} for managed CID {}",
            runtime_vsock.clock_sync_port, runtime_vsock.enclave_cid
        );

        let binding = format!(
            "clock sync host time server vsock port {} for managed CID {}",
            runtime_vsock.clock_sync_port, runtime_vsock.enclave_cid
        );
        let listener = match crate::vsock::serve(runtime_vsock.clock_sync_port) {
            Ok(listener) => listener,
            Err(err) => {
                return handle_clock_sync_bind_error(
                    annotate_host_vsock_bind_error(err, binding),
                    runtime_vsock,
                );
            }
        };
        self.tasks
            .push(utils::spawn!("clock sync time server", async move {
                tokio::pin!(listener);
                while let Some(stream) = listener.next().await {
                    tokio::spawn(async move {
                        if let Err(e) = handle_time_request(stream).await {
                            error!("clock sync: error handling time request: {e}");
                        }
                    });
                }
            })?);

        Ok(())
    }

    fn start_odyn_log_stream(&mut self, cid: u32) -> Result<()> {
        self.tasks
            .push(utils::spawn!("odyn log stream", async move {
                info!("waiting for enclave to boot to stream logs");
                let conn = loop {
                    match VsockStream::connect(cid, APP_LOG_PORT).await {
                        Ok(conn) => break conn,

                        // TODO: improve the polling frequency / backoff / timeout
                        Err(_) => {
                            tokio::time::sleep(LOG_VSOCK_RETRY_INTERVAL).await;
                        }
                    }
                };

                info!("connected to enclave, starting log stream");
                if let Err(e) = utils::log_lines_from_stream("enclave", conn).await {
                    error!("error reading log lines from enclave: {e}");
                }
            })?);

        Ok(())
    }

    async fn await_exit(cid: u32, status_port: u32) -> Result<EnclaveExitStatus> {
        let mut failed_attempts = 0;

        loop {
            let conn = match VsockStream::connect(cid, status_port).await {
                Ok(conn) => conn,

                Err(_) => {
                    failed_attempts += 1;
                    if failed_attempts >= STATUS_VSOCK_RETRY_LIMIT {
                        return Err(anyhow!(
                            "failed to connect to enclave status port after {STATUS_VSOCK_RETRY_LIMIT} attempts"
                        ));
                    }
                    tokio::time::sleep(STATUS_VSOCK_RETRY_INTERVAL).await;
                    continue;
                }
            };

            debug!("connected to enclave status port");

            let mut framed = FramedRead::new(conn, LinesCodec::new_with_max_length(1024));

            while let Some(line_res) = framed.next().await {
                let line = match line_res {
                    Ok(line) => line,
                    Err(e) => {
                        error!("error reading from status port: {e}");
                        continue;
                    }
                };

                let status: EnclaveProcessStatus = match serde_json::from_str(&line) {
                    Ok(status) => status,
                    Err(e) => {
                        error!("error parsing status line: {e}");
                        continue;
                    }
                };

                match status {
                    EnclaveProcessStatus::Exited { code } => {
                        return Ok(EnclaveExitStatus::Exited(code));
                    }
                    EnclaveProcessStatus::Signaled { signal } => {
                        return Ok(EnclaveExitStatus::Signaled(signal));
                    }
                    EnclaveProcessStatus::Fatal { error } => {
                        return Ok(EnclaveExitStatus::Fatal(error));
                    }
                    _ => {
                        debug!("enclave status: {status:#?}");
                    }
                }
            }

            error!("enclave status port closed unexpectedly");
        }
    }

    async fn attach_debug_console(&mut self, enclave_id: &str) -> Result<()> {
        info!("attaching to debug console");

        let stdout = self.cli.console(enclave_id).await?;

        self.tasks.push(tokio::task::spawn(async move {
            if let Err(e) = utils::log_lines_from_stream("nitro-cli::console", stdout).await {
                error!("error reading log lines from debug console: {e}");
            }
        }));

        Ok(())
    }

    async fn cleanup_running_state(&mut self) -> Result<()> {
        if let Some(enclave_info) = self.enclave_info.take() {
            debug!("terminating enclave");
            self.cli.terminate_enclave(&enclave_info.id).await?;
        } else {
            debug!("no enclave to stop");
        }

        self.runtime_vsock = None;
        self.abort_tasks().await;

        Ok(())
    }

    async fn abort_tasks(&mut self) {
        for task in std::mem::take(&mut self.tasks) {
            task.abort();
            match task.await {
                Ok(_) => {}
                Err(e) => {
                    debug!("task terminated with error {e}");
                }
            };
        }
    }
}

fn annotate_host_vsock_bind_error(err: anyhow::Error, binding: String) -> anyhow::Error {
    if is_addr_in_use_error(&err) {
        err.context(format!(
            "failed to bind {binding}: the derived host-side VSOCK port is already in use"
        ))
    } else {
        err.context(format!("failed to bind {binding}"))
    }
}

fn is_addr_in_use_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<std::io::Error>(),
            Some(io_err) if io_err.kind() == std::io::ErrorKind::AddrInUse
        )
    })
}

fn is_managed_cid_conflict_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<crate::nitro_cli::NitroCliCommandFailure>()
            .is_some_and(|failure| failure.indicates_cid_conflict())
    })
}

fn handle_clock_sync_bind_error(
    err: anyhow::Error,
    runtime_vsock: &RuntimeHostVsockPorts,
) -> Result<()> {
    if is_addr_in_use_error(&err) {
        warn!(
            "failed to bind host-side clock sync time server on vsock port {} for managed CID {}: {err:#}; continuing without a dedicated clock sync listener",
            runtime_vsock.clock_sync_port, runtime_vsock.enclave_cid
        );
        return Ok(());
    }

    Err(err)
}

fn ensure_managed_cid_retry_budget(conflict_rejected_cids: &HashSet<u32>) -> Result<()> {
    if conflict_rejected_cids.len() >= MANAGED_CID_CONFLICT_RETRY_LIMIT {
        anyhow::bail!(
            "failed to start enclave after {} managed CID conflict retries; exhausted CIDs: {:?}",
            MANAGED_CID_CONFLICT_RETRY_LIMIT,
            conflict_rejected_cids
        );
    }

    Ok(())
}

/// Handle a single clock sync time request from the enclave.
/// Reads a request line, responds with host receive/transmit timestamps as JSON.
#[cfg(feature = "vsock")]
async fn handle_time_request(stream: tokio_vsock::VsockStream) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = FramedRead::new(
        reader,
        LinesCodec::new_with_max_length(CLOCK_SYNC_MAX_REQUEST_LEN),
    );
    let line = tokio::time::timeout(CLOCK_SYNC_REQUEST_TIMEOUT, reader.next())
        .await
        .map_err(|_| anyhow!("clock sync request timed out"))?
        .ok_or_else(|| anyhow!("clock sync client closed connection before sending a request"))??;

    if line != "time" {
        return Err(anyhow!("invalid clock sync request: expected 'time'"));
    }

    let server_receive = current_unix_timestamp()?;

    // Build the static prefix first so t3 is sampled as close to write_all as possible.
    let mut resp_line = format!(
        "{{\"server_receive_secs\":{},\"server_receive_nanos\":{},",
        server_receive.0, server_receive.1,
    );
    let server_transmit = current_unix_timestamp()?;
    writeln!(
        resp_line,
        "\"server_transmit_secs\":{},\"server_transmit_nanos\":{}}}",
        server_transmit.0, server_transmit.1,
    )?;
    writer.write_all(resp_line.as_bytes()).await?;
    writer.flush().await?;

    debug!("clock sync: served time to enclave");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nitro_cli::NitroCliCommandFailure;
    use crate::runtime_vsock::RuntimeHostVsockPorts;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn managed_cid_conflict_detection_requires_nitro_cli_stderr_match() {
        let err = anyhow::Error::new(NitroCliCommandFailure::new(
            "run-enclave --enclave-cid 19".to_string(),
            std::process::ExitStatus::from_raw(1 << 8),
            "Enclave CID 19 is already in use by another enclave".to_string(),
        ));
        assert!(is_managed_cid_conflict_error(&err));

        let other = anyhow::Error::msg("some unrelated startup failure");
        assert!(!is_managed_cid_conflict_error(&other));
    }

    #[test]
    fn clock_sync_addr_in_use_degrades_gracefully() {
        let runtime_vsock = RuntimeHostVsockPorts::for_cid(16).unwrap();
        let err = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "port already in use",
        ));
        assert!(handle_clock_sync_bind_error(err, &runtime_vsock).is_ok());
    }

    #[test]
    fn clock_sync_non_addr_in_use_still_errors() {
        let runtime_vsock = RuntimeHostVsockPorts::for_cid(16).unwrap();
        let err = anyhow::Error::msg("some other failure");
        assert!(handle_clock_sync_bind_error(err, &runtime_vsock).is_err());
    }

    #[test]
    fn managed_cid_retry_budget_is_bounded() {
        let budget = (0..MANAGED_CID_CONFLICT_RETRY_LIMIT as u32).collect::<HashSet<_>>();
        let err = ensure_managed_cid_retry_budget(&budget)
            .unwrap_err()
            .to_string();
        assert!(err.contains("managed CID conflict retries"));
    }
}

fn current_unix_timestamp() -> Result<(i64, u32)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("system time error: {e}"))?;

    let secs = i64::try_from(now.as_secs())
        .map_err(|_| anyhow!("system time seconds do not fit into i64"))?;

    Ok((secs, now.subsec_nanos()))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
enum EnclaveProcessStatus {
    #[serde(rename = "running")]
    Running,

    #[serde(rename = "exited")]
    Exited { code: i32 },

    #[serde(rename = "signaled")]
    Signaled { signal: i32 },

    #[serde(rename = "fatal")]
    Fatal { error: String },
}

#[derive(Debug)]
pub enum EnclaveExitStatus {
    Cancelled,
    Exited(i32),
    Signaled(i32),
    Fatal(String),
}
