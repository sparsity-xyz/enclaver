use std::sync::Arc;

use anyhow::{Result, anyhow};
use log::info;
use tokio::task::JoinHandle;

use crate::config::Configuration;
use enclaver::policy::EgressPolicy;
use enclaver::proxy::egress_http::EnclaveHttpProxy;
use enclaver::runtime_vsock::RuntimeHostVsockPorts;

pub struct EgressService {
    proxy: Option<JoinHandle<()>>,
}

impl EgressService {
    pub async fn start(
        config: &Configuration,
        runtime_vsock: &RuntimeHostVsockPorts,
    ) -> Result<Self> {
        let task = if let Some(proxy_uri) = config.egress_proxy_uri()? {
            info!("Starting egress");

            let egress = config.manifest.egress.as_ref().ok_or_else(|| {
                anyhow!("invariant violated: egress proxy URI requires manifest.egress")
            })?;
            let proxy_port = proxy_uri.port_u16().ok_or_else(|| {
                anyhow!("invariant violated: egress proxy URI must include a TCP port")
            })?;
            let policy = Arc::new(EgressPolicy::new(egress));
            let host_egress_port = runtime_vsock.egress_port;

            let proxy = EnclaveHttpProxy::bind(proxy_port).await?;
            set_proxy_env_vars(config)?;

            Some(tokio::task::spawn(async move {
                proxy.serve(host_egress_port, policy).await;
            }))
        } else {
            None
        };

        Ok(Self { proxy: task })
    }

    pub async fn stop(self) {
        if let Some(proxy) = self.proxy {
            proxy.abort();
            _ = proxy.await;
        }
    }
}

fn set_proxy_env_vars(config: &Configuration) -> Result<()> {
    unsafe {
        // SAFETY: While not 100% b/c it is a multi-threaded program, with 3rd party code,
        // we only get/set env vars in a ::start() methods that are serialized via .await.
        for (name, value) in config.egress_proxy_env_vars()? {
            std::env::set_var(name, value);
        }
    }
    Ok(())
}
