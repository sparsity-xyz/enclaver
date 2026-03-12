# Host-Backed Directory Mounts Guide

This guide explains how to give an enclave application a normal writable
directory such as `/mnt/appdata`, while storing the actual bytes on the parent
instance.

In Enclaver, the feature is configured with a manifest-declared
`storage.mounts[]` entry plus a runtime `--mount <name>=<host_state_dir>`
binding, exposed through the hostfs file proxy. If you discard the bound host
state directory between runs, the same mechanism behaves like a host-backed
temporary directory.

Whether the mount behaves as "temporary" or "persistent" depends on the
lifecycle of the bound `host_state_dir`. Reuse the same directory and Enclaver
reuses the same backing image. Discard that directory and the next run starts
from an empty filesystem.

## What You Get

- a normal directory inside the enclave, such as `/mnt/appdata`
- host-backed persistence across enclave restarts when you reuse the same host path
- a per-mount size limit enforced by a fixed-size loopback image
- normal file APIs for the application, without app-specific storage glue

## Quick Example

Manifest:

```yaml
storage:
  mounts:
    - name: appdata
      mount_path: /mnt/appdata
      required: true
      size_mb: 10240
```

Runtime binding:

```bash
enclaver run -f enclaver.yaml --mount appdata=/var/lib/my-service/appdata
```

Result:

- inside the enclave, your application reads and writes `/mnt/appdata`
- on the host, Enclaver creates or reuses a loopback-backed filesystem under
  `/var/lib/my-service/appdata`
- restarting the enclave with the same `--mount` path keeps the data

## Host-Side Layout

`<host_state_dir>` is the host path you pass to `--mount`.

Enclaver stores its runtime metadata under a hidden directory:

```text
<host_state_dir>/
`- .enclaver-hostfs/
   |- disk.img
   |- lock
   `- mnt-<uuid>/
      `- data/
```

For example, if you bind:

```bash
--mount appdata=/var/lib/my-service/appdata
```

then the backing image lives at:

```text
/var/lib/my-service/appdata/.enclaver-hostfs/disk.img
```

What these files are:

- `disk.img`: the durable ext4 loopback image for this mount
- `lock`: prevents the same host state directory from being mounted twice at once
- `mnt-<uuid>/data`: the transient host mountpoint used for the current runtime

The extra `.enclaver-hostfs/` layer is intentional. It keeps Enclaver metadata
separate from the application's host state directory.

`disk.img` is a sparse file. `ls -lh` shows the logical size, while actual disk
usage grows as data is written.

## How Persistence Works

- reusing the same `host_state_dir` preserves files across runs
- deleting `<host_state_dir>/.enclaver-hostfs/` resets the mount to an empty filesystem
- each mount gets its own loopback image and quota
- different mounts cannot share the same `host_state_dir`

## Runtime Flow

1. The manifest declares `storage.mounts[]`.
2. `enclaver run --mount <name>=<host_state_dir>` resolves the runtime binding.
3. The host prepares or reuses `<host_state_dir>/.enclaver-hostfs/disk.img`,
   mounts it on the parent instance, and bind-mounts it into the Sleeve
   container.
4. `enclaver-run` exposes that filesystem through a hostfs proxy on a
   host-side VSOCK port derived from the enclave CID and mount order.
5. `odyn` mounts a FUSE filesystem at the configured `mount_path`.
6. The application starts only after required mounts are ready.

## Operational Notes

- `size_mb` is the storage quota for the mount
- when the image fills, writes fail with `ENOSPC`
- optional mounts are skipped if the matching runtime bind is absent
- required mounts fail startup if the runtime bind or host proxy is unavailable
- host-side prerequisites are `mkfs.ext4`, `mount`, and `umount`
- the EIF kernel must include FUSE support for enclave-side mounting

## Security Model

This storage is host-backed, but it is not trusted.

- the parent instance still controls the backing storage
- the parent instance can tamper with stored bytes
- the parent instance can observe file names, sizes, and access timing
- the enclave must not treat mounted content as trusted code or trusted config

If data must remain trustworthy after it leaves enclave memory, add
application-level encryption, integrity checks, or signatures.

## Filesystem Semantics

The current implementation supports the common file and directory path:

- create/open/read/write/truncate
- mkdir/readdir
- unlink/rmdir
- rename
- fsync/statfs

Symlink and xattr management are not first-class operations. Existing symlinks
are surfaced in metadata and directory listings, but explicit `readlink`,
`symlink`, and xattr operations return `ENOSYS`.

## Implementation Notes

The runtime path is:

```text
host state dir
  -> fixed-size loopback image
  -> host mountpoint on the parent instance
  -> Docker bind mount into the Sleeve container
  -> hostfs proxy in enclaver-run
  -> vsock request/response protocol
  -> FUSE mount in odyn
  -> mount path inside the enclave
  -> application uses normal file APIs
```

The hostfs protocol is a framed JSON protocol over vsock. Each request opens a
fresh vsock connection, performs a `hello` handshake, sends one filesystem
operation, receives one response, and closes the connection.

Current operations:

- `hello`
- `ping`
- `statfs`
- `get_metadata`
- `read_dir`
- `read_file`
- `write_file`
- `set_len`
- `mkdir`
- `remove_file`
- `remove_dir`
- `rename`
- `fsync`

Relevant implementation files:

- `enclaver/src/manifest.rs`
- `enclaver/src/hostfs.rs`
- `enclaver/src/fs_protocol.rs`
- `enclaver/src/hostfs_service.rs`
- `enclaver/src/hostfs_client.rs`
- `enclaver/src/proxy/fs_host.rs`
- `enclaver/src/run.rs`
- `enclaver/src/bin/odyn/fs_mount.rs`
- `enclaver/src/bin/odyn/main.rs`

Linux validation on a Nitro-capable host can be exercised with
`scripts/hostfs-smoke-test.sh`.
