// Path and filename constants
pub const EIF_FILE_NAME: &str = "application.eif";
pub const MANIFEST_FILE_NAME: &str = "enclaver.yaml";

pub const ENCLAVE_CONFIG_DIR: &str = "/etc/enclaver";
pub const ENCLAVE_ODYN_PATH: &str = "/sbin/odyn";

pub const RELEASE_BUNDLE_DIR: &str = "/enclave";

// Port Constants

// start "internal" ports above the 16-bit boundary (reserved for proxying TCP)
pub const STATUS_PORT: u32 = 17000;
pub const APP_LOG_PORT: u32 = 17001;

// Enclaver manages enclave CIDs for `enclaver run` so multiple Enclaver instances
// can coexist on one EC2 without colliding on host-side VSOCK listeners.
pub const ENCLAVER_MANAGED_CID_START: u32 = 16;
pub const ENCLAVER_MANAGED_CID_END: u32 = 4096;

// Host-side runtime listeners are derived from the enclave CID.
pub const HOST_RUNTIME_VSOCK_PORT_BASE: u32 = 20_000;
pub const HOST_RUNTIME_VSOCK_PORT_STRIDE: u32 = 128;
pub const HOST_RUNTIME_EGRESS_OFFSET: u32 = 0;
pub const HOST_RUNTIME_CLOCK_SYNC_OFFSET: u32 = 1;
pub const HOST_RUNTIME_HOSTFS_OFFSET_BASE: u32 = 16;
pub const HOST_RUNTIME_HOSTFS_CAPACITY: u32 =
    HOST_RUNTIME_VSOCK_PORT_STRIDE - HOST_RUNTIME_HOSTFS_OFFSET_BASE;

// Default TCP Port that the egress proxy listens on inside the enclave, if not
// specified in the manifest.
pub const HTTP_EGRESS_PROXY_PORT: u16 = 10000;

// Registry-backed KMS discovery currently requires a Helios endpoint on this
// enclave-local port.
pub const KMS_REGISTRY_HELIOS_PORT: u16 = 18545;

// The hostname to refer to the host side from inside the enclave.
pub const OUTSIDE_HOST: &str = "host";
