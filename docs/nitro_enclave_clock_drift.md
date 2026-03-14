# Clock Drift and Time Sync in Enclaver

## Why this matters

Long-running enclaves can drift relative to the parent instance's wall clock.
That matters for time-sensitive behavior such as:

- JWT validation
- TLS certificate checks
- expiry windows
- any protocol that compares wall-clock timestamps

Enclaver includes host-assisted clock sync so applications do not need to build
this plumbing themselves.

## What Enclaver does today

When clock sync is effectively enabled:

- `enclaver-run` starts a host-side VSOCK time server before launching the enclave
- `odyn` performs an initial sync during startup
- `odyn` keeps syncing periodically after startup
- the default interval is 300 seconds when `clock_sync` is omitted
- the client estimates RTT and clock offset from host receive/transmit timestamps before calling `clock_settime(CLOCK_REALTIME, ...)`

Relevant implementation files:

- `enclaver/src/run.rs`
- `enclaver/src/bin/odyn/clock_sync.rs`
- `enclaver/src/runtime_vsock.rs`
- `enclaver/src/manifest.rs`

## Default behavior

Clock sync is default-on.

- omitting `clock_sync` keeps clock sync enabled
- `clock_sync: {}` also keeps the default behavior
- `clock_sync.enabled: false` disables the feature
- `clock_sync.interval_secs` changes the periodic sync interval

Examples:

```yaml
# Keep defaults by omitting the block entirely

clock_sync:
  enabled: false
```

```yaml
clock_sync:
  interval_secs: 60
```

## Failure behavior

The current implementation is intentionally resilient:

- `odyn` retries the initial sync up to 10 times with a 2-second delay between attempts
- periodic sync failures are logged and retried on the next interval
- on the host side, Enclaver first retries managed CID selection when the clock-sync VSOCK listener collides
- if the host-side retry budget is exhausted and only clock sync is still conflicting, the enclave can still continue without a dedicated clock-sync listener

## What clock sync does not guarantee

Clock sync improves operational correctness, but it is not a trusted time root.

- the enclave follows the parent instance's wall clock
- if the parent instance time is wrong, the synced enclave time is also wrong
- applications that only need elapsed-time measurement should still prefer monotonic time for that purpose

## Operational guidance

- leave clock sync enabled unless you have a deliberate reason to disable it
- if your application depends on JWTs, TLS, or timestamped credentials, verify those flows with clock sync enabled
- if you disable clock sync, expect long-running enclaves to diverge over time and plan for that explicitly

## Related documents

- `docs/odyn.md`
- `docs/odyn_details.md`
- `docs/vsock_runtime.md`
- `docs/enclaver.yaml`
