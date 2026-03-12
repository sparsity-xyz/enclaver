use crate::constants::{
    ENCLAVER_MANAGED_CID_END, ENCLAVER_MANAGED_CID_START, HOST_RUNTIME_CLOCK_SYNC_OFFSET,
    HOST_RUNTIME_EGRESS_OFFSET, HOST_RUNTIME_HOSTFS_CAPACITY, HOST_RUNTIME_HOSTFS_OFFSET_BASE,
    HOST_RUNTIME_VSOCK_PORT_BASE, HOST_RUNTIME_VSOCK_PORT_STRIDE,
};
use anyhow::{Result, anyhow, bail};
use std::collections::HashSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeHostVsockPorts {
    pub enclave_cid: u32,
    pub egress_port: u32,
    pub clock_sync_port: u32,
    hostfs_base_port: u32,
}

impl RuntimeHostVsockPorts {
    pub fn for_cid(enclave_cid: u32) -> Result<Self> {
        validate_enclave_cid(enclave_cid)?;

        let block_base = runtime_block_base(enclave_cid)?;
        let egress_port = block_base
            .checked_add(HOST_RUNTIME_EGRESS_OFFSET)
            .ok_or_else(|| anyhow!("host egress port allocation overflowed"))?;
        let clock_sync_port = block_base
            .checked_add(HOST_RUNTIME_CLOCK_SYNC_OFFSET)
            .ok_or_else(|| anyhow!("host clock sync port allocation overflowed"))?;
        let hostfs_base_port = block_base
            .checked_add(HOST_RUNTIME_HOSTFS_OFFSET_BASE)
            .ok_or_else(|| anyhow!("hostfs base port allocation overflowed"))?;

        Ok(Self {
            enclave_cid,
            egress_port,
            clock_sync_port,
            hostfs_base_port,
        })
    }

    pub fn hostfs_mount_port(&self, index: usize) -> Result<u32> {
        let index_u32 = u32::try_from(index)
            .map_err(|_| anyhow!("hostfs mount index {index} does not fit into u32"))?;
        if index_u32 >= HOST_RUNTIME_HOSTFS_CAPACITY {
            bail!(
                "hostfs mount index {} exceeds the per-enclave hostfs capacity of {} mounts",
                index,
                HOST_RUNTIME_HOSTFS_CAPACITY
            );
        }

        self.hostfs_base_port
            .checked_add(index_u32)
            .ok_or_else(|| anyhow!("hostfs port allocation overflowed"))
    }

    #[cfg(feature = "vsock")]
    pub fn for_local_enclave() -> Result<Self> {
        let cid = vsock_sys::get_local_cid()
            .map_err(|err| anyhow!("failed to read the local enclave CID from AF_VSOCK: {err}"))?;
        Self::for_cid(cid)
    }
}

pub fn allocate_managed_enclave_cid(used: &HashSet<u32>) -> Result<u32> {
    for cid in ENCLAVER_MANAGED_CID_START..=ENCLAVER_MANAGED_CID_END {
        if !used.contains(&cid) {
            return Ok(cid);
        }
    }

    bail!(
        "no free managed enclave CID is available in the configured range {}-{}",
        ENCLAVER_MANAGED_CID_START,
        ENCLAVER_MANAGED_CID_END
    )
}

pub fn validate_enclave_cid(enclave_cid: u32) -> Result<()> {
    if enclave_cid < 4 {
        bail!(
            "enclave CID {} is reserved; Nitro Enclaves CIDs must be >= 4",
            enclave_cid
        );
    }

    // Verify the CID maps to a valid host-side VSOCK block and catch overflow.
    let _ = runtime_block_base(enclave_cid)?;
    Ok(())
}

fn runtime_block_base(enclave_cid: u32) -> Result<u32> {
    HOST_RUNTIME_VSOCK_PORT_BASE
        .checked_add(
            enclave_cid
                .checked_mul(HOST_RUNTIME_VSOCK_PORT_STRIDE)
                .ok_or_else(|| anyhow!("runtime vsock port block allocation overflowed"))?,
        )
        .ok_or_else(|| anyhow!("runtime vsock port block allocation overflowed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        ENCLAVER_MANAGED_CID_START, HOST_RUNTIME_VSOCK_PORT_BASE, HOST_RUNTIME_VSOCK_PORT_STRIDE,
    };

    #[test]
    fn allocate_managed_enclave_cid_skips_used_values() {
        let used = HashSet::from([ENCLAVER_MANAGED_CID_START, 99]);
        let cid = allocate_managed_enclave_cid(&used).unwrap();
        assert_eq!(cid, ENCLAVER_MANAGED_CID_START + 1);
    }

    #[test]
    fn runtime_ports_for_first_managed_cid_are_deterministic() {
        let ports = RuntimeHostVsockPorts::for_cid(ENCLAVER_MANAGED_CID_START).unwrap();
        let block_base = HOST_RUNTIME_VSOCK_PORT_BASE
            + (ENCLAVER_MANAGED_CID_START * HOST_RUNTIME_VSOCK_PORT_STRIDE);

        assert_eq!(ports.egress_port, block_base);
        assert_eq!(ports.clock_sync_port, block_base + 1);
        assert_eq!(ports.hostfs_mount_port(0).unwrap(), block_base + 16);
    }

    #[test]
    fn hostfs_mount_port_rejects_indices_beyond_per_enclave_capacity() {
        let ports = RuntimeHostVsockPorts::for_cid(ENCLAVER_MANAGED_CID_START).unwrap();
        let err = ports
            .hostfs_mount_port(HOST_RUNTIME_HOSTFS_CAPACITY as usize)
            .unwrap_err()
            .to_string();

        assert!(err.contains("per-enclave hostfs capacity"));
    }

    #[test]
    fn validate_enclave_cid_rejects_reserved_values() {
        let err = validate_enclave_cid(3).unwrap_err().to_string();
        assert!(err.contains("reserved"));
    }

    #[test]
    fn runtime_ports_reject_overflowing_cids() {
        let err = RuntimeHostVsockPorts::for_cid(u32::MAX)
            .unwrap_err()
            .to_string();
        assert!(err.contains("overflow"));
    }

    #[test]
    fn runtime_ports_accept_upper_managed_cid() {
        assert!(RuntimeHostVsockPorts::for_cid(ENCLAVER_MANAGED_CID_END).is_ok());
    }

    #[test]
    fn runtime_port_blocks_for_distinct_cids_do_not_overlap() {
        let first = RuntimeHostVsockPorts::for_cid(ENCLAVER_MANAGED_CID_START).unwrap();
        let second = RuntimeHostVsockPorts::for_cid(ENCLAVER_MANAGED_CID_START + 1).unwrap();

        assert_ne!(first.egress_port, second.egress_port);
        assert_ne!(first.clock_sync_port, second.clock_sync_port);
        assert_ne!(
            first.hostfs_mount_port(0).unwrap(),
            second.hostfs_mount_port(0).unwrap()
        );
    }
}
