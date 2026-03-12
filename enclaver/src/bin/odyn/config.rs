use anyhow::{Result, anyhow};
use http::Uri;
use std::path::{Path, PathBuf};

use enclaver::constants::{HTTP_EGRESS_PROXY_PORT, MANIFEST_FILE_NAME};
use enclaver::manifest::{HeliosRpcKind, Manifest};

const LOOPBACK_NO_PROXY: &str = "localhost,127.0.0.1";

#[derive(Clone, Debug)]
pub struct HeliosRuntimeConfig {
    pub kind: HeliosRpcKind,
    pub network: String,
    pub execution_rpc: String,
    pub consensus_rpc: Option<String>,
    pub checkpoint: Option<String>,
    pub listen_port: u16,
    pub chain_name: String,
}

pub struct Configuration {
    pub config_dir: PathBuf,
    pub manifest: Manifest,
    pub listener_ports: Vec<u16>,
}

impl Configuration {
    fn from_manifest(config_dir: &Path, manifest: Manifest) -> Self {
        let listener_ports = manifest
            .ingress
            .as_ref()
            .map(|ingress| ingress.iter().map(|item| item.listen_port).collect())
            .unwrap_or_default();

        Self {
            config_dir: config_dir.to_path_buf(),
            manifest,
            listener_ports,
        }
    }

    pub async fn load<P: AsRef<Path>>(config_dir: P) -> Result<Self> {
        let mut manifest_path = config_dir.as_ref().to_path_buf();
        manifest_path.push(MANIFEST_FILE_NAME);

        let manifest = enclaver::manifest::load_manifest(&manifest_path).await?;
        Ok(Self::from_manifest(config_dir.as_ref(), manifest))
    }

    pub fn load_blocking<P: AsRef<Path>>(config_dir: P) -> Result<Self> {
        let mut manifest_path = config_dir.as_ref().to_path_buf();
        manifest_path.push(MANIFEST_FILE_NAME);

        let manifest = enclaver::manifest::load_manifest_sync(&manifest_path)?;
        Ok(Self::from_manifest(config_dir.as_ref(), manifest))
    }

    pub fn egress_proxy_uri(&self) -> Result<Option<Uri>> {
        if self.manifest.egress_proxy_enabled() {
            let port = self
                .manifest
                .egress
                .as_ref()
                .and_then(|egress| egress.proxy_port)
                .unwrap_or(HTTP_EGRESS_PROXY_PORT);

            let proxy_uri = format!("http://127.0.0.1:{port}")
                .parse::<Uri>()
                .map_err(|err| {
                    anyhow!("failed to build egress proxy URI for port {port}: {err}")
                })?;

            Ok(Some(proxy_uri))
        } else {
            Ok(None)
        }
    }

    pub fn egress_proxy_env_vars(&self) -> Result<Vec<(String, String)>> {
        let Some(proxy_uri) = self.egress_proxy_uri()? else {
            return Ok(Vec::new());
        };

        let proxy = proxy_uri.to_string();
        Ok(vec![
            ("http_proxy".to_string(), proxy.clone()),
            ("https_proxy".to_string(), proxy.clone()),
            ("HTTP_PROXY".to_string(), proxy.clone()),
            ("HTTPS_PROXY".to_string(), proxy),
            ("no_proxy".to_string(), LOOPBACK_NO_PROXY.to_string()),
            ("NO_PROXY".to_string(), LOOPBACK_NO_PROXY.to_string()),
        ])
    }

    pub fn api_port(&self) -> Option<u16> {
        self.manifest.api.as_ref().map(|a| a.listen_port)
    }

    pub fn aux_api_port(&self) -> Option<u16> {
        self.manifest.effective_aux_api_port()
    }

    pub fn s3_config(&self) -> Option<&enclaver::manifest::S3StorageConfig> {
        self.manifest
            .storage
            .as_ref()
            .and_then(|s| s.s3.as_ref())
            .filter(|s3| s3.enabled)
    }

    pub fn kms_integration_config(&self) -> Option<&enclaver::manifest::KmsIntegration> {
        self.manifest
            .kms_integration
            .as_ref()
            .filter(|kms| kms.enabled)
    }

    pub fn helios_configs(&self) -> Vec<HeliosRuntimeConfig> {
        let Some(helios) = self.manifest.helios_rpc.as_ref().filter(|h| h.enabled) else {
            return Vec::new();
        };
        let Some(chains) = helios.chains.as_ref() else {
            return Vec::new();
        };

        let mut configs = Vec::with_capacity(chains.len());
        for chain in chains {
            configs.push(HeliosRuntimeConfig {
                kind: chain.kind.clone(),
                network: chain.network.clone(),
                execution_rpc: chain.execution_rpc.clone(),
                consensus_rpc: chain.consensus_rpc.clone(),
                checkpoint: chain.checkpoint.clone(),
                listen_port: chain.local_rpc_port,
                chain_name: chain.name.clone(),
            });
        }

        configs
    }

    pub fn clock_sync_config(&self) -> Option<enclaver::manifest::ClockSync> {
        let clock_sync = self.manifest.effective_clock_sync();
        clock_sync.enabled.then_some(clock_sync)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclaver::constants::KMS_REGISTRY_HELIOS_PORT;
    use enclaver::manifest::{Api, AuxApi, ClockSync, Egress, HeliosRpc, HeliosRpcChain, Sources};

    fn base_config() -> Configuration {
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
                api: Some(Api { listen_port: 9000 }),
                aux_api: None,
                storage: None,
                kms_integration: None,
                helios_rpc: None,
                clock_sync: None,
            },
            listener_ports: Vec::new(),
        }
    }

    #[test]
    fn aux_api_port_defaults_to_api_plus_one() {
        let cfg = base_config();
        assert_eq!(cfg.aux_api_port(), Some(9001));
    }

    #[test]
    fn aux_api_port_uses_explicit_value() {
        let mut cfg = base_config();
        cfg.manifest.aux_api = Some(AuxApi {
            listen_port: Some(9100),
        });
        assert_eq!(cfg.aux_api_port(), Some(9100));
    }

    #[test]
    fn aux_api_port_with_max_api_and_explicit_value_does_not_overflow() {
        let mut cfg = base_config();
        cfg.manifest.api = Some(Api {
            listen_port: u16::MAX,
        });
        cfg.manifest.aux_api = Some(AuxApi {
            listen_port: Some(9001),
        });
        assert_eq!(cfg.aux_api_port(), Some(9001));
    }

    #[test]
    fn aux_api_port_with_max_api_and_no_aux_returns_none_for_invalid_manifest_shape() {
        let mut cfg = base_config();
        cfg.manifest.api = Some(Api {
            listen_port: u16::MAX,
        });
        cfg.manifest.aux_api = None;
        assert_eq!(cfg.aux_api_port(), None);
    }

    #[test]
    fn helios_configs_returns_empty_when_disabled() {
        let mut cfg = base_config();
        cfg.manifest.helios_rpc = Some(HeliosRpc {
            enabled: false,
            chains: None,
        });

        let configs = cfg.helios_configs();
        assert!(configs.is_empty());
    }

    #[test]
    fn helios_configs_prefers_helios_rpc_chains() {
        let mut cfg = base_config();
        cfg.manifest.helios_rpc = Some(HeliosRpc {
            enabled: true,
            chains: Some(vec![
                HeliosRpcChain {
                    name: "L2-base-sepolia".to_string(),
                    network_id: Some("84532".to_string()),
                    kind: HeliosRpcKind::Opstack,
                    network: "base-sepolia".to_string(),
                    execution_rpc: "https://sepolia.base.example".to_string(),
                    consensus_rpc: None,
                    checkpoint: None,
                    local_rpc_port: KMS_REGISTRY_HELIOS_PORT,
                },
                HeliosRpcChain {
                    name: "ethereum-mainnet".to_string(),
                    network_id: Some("1".to_string()),
                    kind: HeliosRpcKind::Ethereum,
                    network: "mainnet".to_string(),
                    execution_rpc: "https://eth.example".to_string(),
                    consensus_rpc: None,
                    checkpoint: None,
                    local_rpc_port: 18546,
                },
            ]),
        });

        let configs = cfg.helios_configs();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].chain_name, "L2-base-sepolia");
        assert_eq!(configs[1].chain_name, "ethereum-mainnet");
    }

    #[test]
    fn clock_sync_defaults_to_enabled_when_omitted() {
        let cfg = base_config();

        let clock_sync = cfg
            .clock_sync_config()
            .expect("clock sync should default to enabled");

        assert!(clock_sync.enabled);
        assert_eq!(clock_sync.interval_secs, 300);
    }

    #[test]
    fn clock_sync_can_be_disabled_explicitly() {
        let mut cfg = base_config();
        cfg.manifest.clock_sync = Some(ClockSync {
            enabled: false,
            interval_secs: 300,
        });

        assert!(cfg.clock_sync_config().is_none());
    }

    #[test]
    fn clock_sync_uses_custom_interval_when_configured() {
        let mut cfg = base_config();
        cfg.manifest.clock_sync = Some(ClockSync {
            enabled: true,
            interval_secs: 42,
        });

        let clock_sync = cfg
            .clock_sync_config()
            .expect("clock sync should remain enabled");

        assert_eq!(clock_sync.interval_secs, 42);
    }

    #[test]
    fn egress_proxy_env_vars_returns_expected_process_env() {
        let mut cfg = base_config();
        cfg.manifest.egress = Some(Egress {
            allow: Some(vec!["https://api.example.com".to_string()]),
            deny: None,
            proxy_port: Some(8123),
        });

        let vars = cfg.egress_proxy_env_vars().unwrap();

        assert!(vars.contains(&(
            "http_proxy".to_string(),
            "http://127.0.0.1:8123/".to_string()
        )));
        assert!(vars.contains(&("NO_PROXY".to_string(), LOOPBACK_NO_PROXY.to_string())));
    }

    #[test]
    fn egress_proxy_env_vars_is_empty_when_egress_is_disabled() {
        let cfg = base_config();
        assert!(cfg.egress_proxy_env_vars().unwrap().is_empty());
    }

    #[test]
    fn helios_configs_returns_empty_when_no_chains() {
        let mut cfg = base_config();
        cfg.manifest.helios_rpc = Some(HeliosRpc {
            enabled: true,
            chains: None,
        });

        let configs = cfg.helios_configs();
        assert!(configs.is_empty());
    }
}
