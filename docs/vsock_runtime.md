# Enclaver VSOCK Runtime Model

This document describes how Enclaver uses VSOCK today, including how multiple
`enclaver run` processes can coexist on the same EC2 instance.

Scope:
- host/container/enclave VSOCK handling at runtime
- managed enclave CID allocation
- host-side runtime VSOCK port derivation
- retry and cleanup behavior when multiple Enclaver instances run concurrently

## Overview

Enclaver uses two kinds of VSOCK ports:

1. Fixed enclave-local VSOCK ports
   - These are stable inside every enclave instance.
   - They are used for app status and app log streaming.

2. Host-side runtime VSOCK ports derived from the enclave CID
   - These are not globally fixed.
   - They are derived from the managed enclave CID chosen for a specific run.
   - They are used for egress, clock sync, and hostfs.

That split is what makes multi-instance support possible:

- The enclave always knows where to expose status and logs.
- The host and the enclave both derive the same host-side runtime ports from
  the enclave CID, so separate enclaves get separate host-side VSOCK blocks.

## Fixed Enclave-local VSOCK Ports

These ports are the same for every enclave:

- status: `17000`
- app log stream: `17001`

They are safe to keep fixed because the host connects to them using:

- enclave CID
- enclave-local port

So two enclaves can both listen on `17000` and `17001` without conflict as long
as their CIDs differ.

## Host-side Runtime VSOCK Port Block

Enclaver derives host-side runtime VSOCK listeners from the managed enclave CID
using this formula:

- block base: `20000 + (CID * 128)`
- egress: `block base + 0`
- clock sync: `block base + 1`
- hostfs mount `N`: `block base + 16 + N`

Example:

- CID `16`
  - egress: `22048`
  - clock sync: `22049`
  - first hostfs mount: `22064`

- CID `17`
  - egress: `22176`
  - clock sync: `22177`
  - first hostfs mount: `22192`

This is implemented in `enclaver/src/runtime_vsock.rs` via
`RuntimeHostVsockPorts`.

## Managed Enclave CID Range

Enclaver does not let each run pick an arbitrary CID from the manifest.

Instead, `enclaver-run` allocates a managed CID from the configured range:

- start: `16`
- end: `4096`

The allocator currently picks the lowest free CID that is not already reported
by `nitro-cli describe-enclaves` and is not already rejected by the current
retry loop.

This is simple and deterministic:

- easy to reason about
- easy to debug from logs
- good enough as long as collision retries are in place

## Startup Sequence

At a high level, `enclaver run` / `enclaver-run` does this:

1. Load the packaged manifest.
2. Query existing enclaves with `nitro-cli describe-enclaves`.
3. Pick a managed CID from the free range.
4. Derive the host-side runtime VSOCK block from that CID.
5. Bind host-side runtime services before launching the enclave:
   - egress proxy
   - hostfs proxies
   - clock sync listener
6. Launch `nitro-cli run-enclave --enclave-cid <CID>`.
7. Once the enclave is running, connect to its fixed status/log VSOCK ports and
   start host-side ingress forwarding.

The key point is step 5:

- host-side runtime VSOCK listeners are bound before the enclave starts
- this guarantees that Odyn can immediately dial the host-side services once it
  boots

## How Odyn Finds the Host-side Runtime Ports

Odyn does not receive the runtime port block over a separate control channel.

Instead, inside the enclave it:

1. Reads its local enclave CID from AF_VSOCK.
2. Recomputes the same `RuntimeHostVsockPorts` layout locally.
3. Uses the derived host-side VSOCK ports for:
   - egress
   - clock sync
   - hostfs mounts

This is why host and enclave stay aligned without needing a `vsock_ports`
runtime config surface.

## Multiple `enclaver run` Processes on One EC2

When two or more Enclaver instances start on the same EC2 instance, they may
race in two places:

1. CID allocation race
2. host-side VSOCK bind race

### 1. CID Allocation Race

Two processes can both observe the same CID as "free" from
`nitro-cli describe-enclaves` and choose it.

Enclaver handles this by:

- launching the enclave with an explicit managed CID
- checking Nitro CLI failures for CID-conflict stderr
- rejecting that CID and retrying with another one

There is an outer retry budget for this path.

### 2. Host-side VSOCK Bind Race

Two processes can derive the same runtime block and attempt to bind the same
host-side VSOCK listeners.

Enclaver handles this by:

- treating `AddrInUse` while binding host-side runtime services as a CID-level
  collision
- rejecting that CID for the current start attempt
- allocating another CID and retrying

There is an inner retry budget for this path.

As a result:

- multiple Enclaver instances can coexist on the same EC2 instance
- each successful instance ends up with a distinct CID
- each successful instance gets a distinct host-side runtime VSOCK block

## Clock Sync Special Case

Clock sync is treated as non-critical compared with enclave startup itself.

Current behavior:

- Enclaver first retries managed CID selection when clock sync bind hits
  `AddrInUse`, just like the other host-side runtime listeners.
- If the runtime bind retry budget is exhausted and only clock sync is still in
  conflict, Enclaver degrades gracefully and starts without a dedicated clock
  sync listener.

This means:

- Enclaver prefers a clean per-CID clock sync listener when possible
- but clock sync does not block the entire enclave forever once retry budget is
  exhausted

## HostFS Mount Ordering

HostFS uses the mount order from `storage.mounts` in the manifest.

That order defines the hostfs offset inside the per-CID VSOCK block:

- mount index `0` -> `block base + 16`
- mount index `1` -> `block base + 17`
- and so on
- the current layout reserves 112 hostfs mount slots per enclave (`128 - 16`)

Both sides must walk the mounts in the same order:

- host side starts one hostfs proxy per mount in manifest order
- Odyn derives the same port from local CID and manifest order

This is why mount order is part of the runtime contract.

## What Still Must Be Globally Unique

VSOCK is only one layer of the runtime.

Even though multiple Enclaver instances can now coexist on one EC2 instance,
the following still need unique host-level assignments:

- Docker-published TCP ports from `enclaver run -p host:container`
- any other host TCP/UDP listeners you bind outside the enclave runtime

VSOCK collision handling does not make Docker `-p` conflicts go away.

## Cleanup Behavior

When Enclaver cleans up a running enclave, it now tries to be best-effort:

- always stop local background tasks
- always stop the debug console process
- always clear local runtime VSOCK state
- only clear the stored enclave identity after a successful
  `terminate-enclave`

If enclave termination fails, the caller now gets an error instead of silently
returning success.

## Important Consequences

- `vsock_ports` is no longer a supported manifest field.
- Host and enclave both derive runtime VSOCK ports from CID instead of reading
  a user-provided runtime port map.
- Running multiple Enclaver instances on the same EC2 instance is supported for
  VSOCK runtime services.
- Docker `-p` host port conflicts are still the operator's responsibility.

## Related Documents

- `docs/port_handling.md`
- `docs/odyn.md`
- `docs/odyn_details.md`
- `docs/architecture.md`
- `docs/enclaver-architecture.md`
