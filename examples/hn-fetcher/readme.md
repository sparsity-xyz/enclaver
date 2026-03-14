# hn-fetcher — example HTTP forwarder

This is a minimal example app that forwards an HTTP GET to an upstream host (news.ycombinator.com) and returns the upstream response.

Current example conventions:
- the app exposes `GET /health` for a quick local/enclave liveness check
- proxy use is explicit in code, matching Enclaver's current egress guidance
- the manifest exposes both the app (`8000`) and Aux API (`9001`) through `ingress`

This app does not call Odyn's internal APIs itself. It is just a minimal
egress-proxy example, so there is no `IN_ENCLAVE` mode switch in the app code or
Dockerfile.

Validated on March 14, 2026 on `app-node`:
- host: Amazon Linux 2023 x86_64
- `enclaver 1.7.2`
- `docker 25.0.14`

The output snippets below are the observed results from that validation run.
Values such as Hacker News page content, image IDs, PCRs, Ethereum addresses, and
attestation size can change on later runs.

## Build app image and run

Build the app image with:

```bash
docker build -t hn-fetcher .
```

Verify the app image with:

```bash
docker images hn-fetcher:latest
```

Observed on `app-node` on March 14, 2026:
```bash
$ docker images hn-fetcher:latest
REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
hn-fetcher   latest    4a906fcc5a99   10 minutes ago  177MB
```

You can run the app image directly with:

```bash
docker run --rm -p 8000:8000 hn-fetcher
curl http://localhost:8000/health
curl -sS http://localhost:8000/ | grep -o -m1 '<title>[^<]*</title>'
```

Observed on `app-node` on March 14, 2026:

```bash
$ curl http://localhost:8000/health
{"ok":true,"upstream":"https://news.ycombinator.com"}

$ curl -sS http://localhost:8000/ | grep -o -m1 '<title>[^<]*</title>'
<title>Hacker News</title>
```

## Build the enclaver image

The content of `enclaver.yaml` is:

```yaml
version: v1
name: "hn-fetcher"
target: "hn-fetcher-enclave:latest"
sources:
  app: "hn-fetcher:latest"
  #odyn: "odyn:latest"
  #sleeve: "sleeve:latest"
defaults:
  memory_mb: 1500
ingress:
  - listen_port: 8000
  - listen_port: 9001
egress:
  allow:
    - news.ycombinator.com
api:
  listen_port: 9000
aux_api:
  listen_port: 9001
```

The manifest includes:
- `ingress` - Allows external HTTP traffic on port 8000
- `ingress` - Also exposes Aux API on port 9001 for the demo API calls below
- `egress` - Allows outbound requests to news.ycombinator.com
- `api` - Enables the internal API service on port 9000 (provides attestation, signing, encryption, and randomness)
- `aux_api` - Enables the auxiliary API on port 9001 (provides controlled external access to select API endpoints)

Then build enclaver image with command:

```bash
enclaver build -f enclaver.yaml
```

Observed on `app-node` on March 14, 2026:

```bash
$ enclaver build -f enclaver.yaml
 INFO  enclaver::build > using app image: sha256:4a906fcc5a99840e1ddd00a833633c9aa90b11ede96e8650e9e2582811bb41fc
 INFO  enclaver::build > using nitro-cli image: sha256:945f75bbfe02ef6ac2bcefe12f21b9902a6dac5ea890778c30ff83bfcafd8e58
 INFO  enclaver::build > built intermediate image: sha256:022089a4434c85ab3cd60cdfd0912df1494c24fde47e69d146aef2e9efe6bed7
 INFO  enclaver::build > started nitro-cli build-eif in container: 67c9bce01b98e8adffa3899e02093b7a7e0c4381263996b9d655831bff0e7c12
 INFO  nitro-cli::build-eif > Start building the Enclave Image...
 INFO  nitro-cli::build-eif > Enclave Image successfully created.
 INFO  enclaver::build      > packaging EIF into release image
{
  "Sources": {
    "App": {
      "ID": "sha256:4a906fcc5a99840e1ddd00a833633c9aa90b11ede96e8650e9e2582811bb41fc"
    },
    "Odyn": {
      "ID": "sha256:5f58abc85d9ef1ab317651c6e069ec58600dc38939228f4abdb5e437f57e3444",
      "Name": "public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest",
      "RepoDigest": "public.ecr.aws/d4t4u8d2/sparsity-ai/odyn@sha256:45d8898dc2cbae0f5d3e65f42639ce6b05c591a09098fb6268b3ab43e925e514"
    },
    "NitroCLI": {
      "ID": "sha256:945f75bbfe02ef6ac2bcefe12f21b9902a6dac5ea890778c30ff83bfcafd8e58",
      "Name": "public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest",
      "RepoDigest": "public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli@sha256:512d98b17f72bc610cd0b7e0d851971f1ca33717d5dc48ac49517d29da009568"
    },
    "Sleeve": {
      "ID": "sha256:67b05859252d4a98a77573eea5481125ffcc2b0c33cc6f11420dd76cc107e417",
      "Name": "public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest",
      "RepoDigest": "public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve@sha256:2057482f199b092d31407cb7107a3b2e74b3d96b7fb29739942fc28687bc8f27"
    }
  },
  "Measurements": {
    "PCR0": "9b86f0489c6c104a0f0952bf444dbabb447544acc573be5ec5ee40ecf8b80ad1deed98161fceddbb14e953b4502f66bd",
    "PCR1": "18b701b9e237424633a37b610308dcf15fb18a25fe12c80d9766b82661b3ecddae6825c6bc13b8fa254f72a87c177d40",
    "PCR2": "31cecadc8d56c371099dd7fbc5735ed2ab59c7dfd5d9be83b3a913e899121b116b8ebb7f086eb5085b46c3e54819df6d"
  },
  "Image": {
    "ID": "sha256:4ce84925ecf49e1eb4105ee0f1ca5d4e3d51da6fe859248ea0846f35d8431127",
    "Name": "hn-fetcher-enclave:latest"
  }
}
```

Verify the enclave image with:

```bash
docker images hn-fetcher-enclave:latest
```
Observed on `app-node` on March 14, 2026:

```bash
$ docker images hn-fetcher-enclave:latest
REPOSITORY           TAG       IMAGE ID       CREATED         SIZE
hn-fetcher-enclave   latest    4ce84925ecf4   3 minutes ago   265MB
```

## Run enclaver image

Run the enclave image with:
```bash
enclaver run -f enclaver.yaml --publish 8000:8000 --publish 9001:9001
```

Test the application:
```bash
curl http://localhost:8000/health
curl -sS http://localhost:8000/ | grep -o -m1 '<title>[^<]*</title>'
curl http://localhost:9001/v1/eth/address
```

Observed on `app-node` on March 14, 2026:

```bash
$ curl http://localhost:8000/health
{"ok":true,"upstream":"https://news.ycombinator.com"}

$ curl -sS http://localhost:8000/ | grep -o -m1 '<title>[^<]*</title>'
<title>Hacker News</title>

$ curl http://localhost:9001/v1/eth/address
{"address":"0x59d006663ebbc03dffdf0ae5ad7e4c87d0d602bf","public_key":"0x046328d0678ca4489f2f4da423d93361b9e345b0c153fef69ae82f698a675c09e2fc8e8e378670559a9319e54e2e2b3b01280623f47b883324a6e17f885022d66d"}
```

What this run command does:
- reads `target` from `enclaver.yaml`
- publishes app traffic on `8000`
- publishes the Aux API on `9001`
- keeps the API exposure aligned with the manifest instead of repeating the image tag manually

## Using the Auxiliary API

The auxiliary API provides controlled external access to enclave functionality. It proxies requests to the internal API while sanitizing inputs to prevent external callers from overriding security-critical defaults.

### Available Endpoints

#### Get Ethereum Address

Retrieve the enclave's Ethereum address derived from the enclave's keypair:

```bash
curl http://localhost:9001/v1/eth/address
```

Example response:
```json
{
  "address": "0x59d006663ebbc03dffdf0ae5ad7e4c87d0d602bf",
  "public_key": "0x046328d0678ca4489f2f4da423d93361b9e345b0c153fef69ae82f698a675c09e2fc8e8e378670559a9319e54e2e2b3b01280623f47b883324a6e17f885022d66d"
}
```

#### Get Encryption Public Key

Retrieve the enclave's P-384 encryption public key:

```bash
curl http://localhost:9001/v1/encryption/public_key
```

Example response:
```json
{
  "public_key_der": "0x3076301006072a8648ce3d020106052b81040022036200042643f747b004cb7ba74098e4f3f859fe6109b8c7c08fff83694eaf7794c588338f5224ab970cbb6edfbbb1931466c96e64c8e1dfaa09bbee9d96fce6ba1d475806efcf52badd4bfee198dddbae882fee3d89085dd067d7818f7e51828718dd1e",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEJkP3R7AEy3unQJjk8/hZ/mEJuMfAj/+D\naU6vd5TFiDOPUiSrlwy7bt+7sZMUZsluZMjh36oJu+6dlvzmuh1HWAbvz1K63Uv+\n4Zjd266IL+49iQhd0GfXgY9+UYKHGN0e\n-----END PUBLIC KEY-----"
}
```

#### Request Attestation

Request an attestation document from the enclave. You can optionally provide a nonce for freshness:

```bash
# Request attestation with default parameters
curl -X POST http://localhost:9001/v1/attestation \
  -H "Content-Type: application/json" \
  -d '{}'

# Request attestation with a custom nonce
curl -X POST http://localhost:9001/v1/attestation \
  -H "Content-Type: application/json" \
  -d '{"nonce": "your-base64-encoded-nonce-here"}'
```

Example response:
The response body is raw CBOR bytes with `Content-Type: application/cbor`, not JSON.
The following was observed on `app-node` on March 14, 2026:

```bash
$ curl -sS -D - -o attestation.cbor -X POST http://localhost:9001/v1/attestation \
  -H "Content-Type: application/json" \
  -d '{}'
HTTP/1.1 200 OK
content-type: application/cbor
content-length: 4649
date: Sat, 14 Mar 2026 00:07:15 GMT
access-control-allow-origin: *

$ wc -c attestation.cbor
4649 attestation.cbor

$ sha256sum attestation.cbor
36f9b9eafdbb7759e7a6c95a2e0142147aa2fc41c7f6a73062ccff218e05c1d1  attestation.cbor
```

If you want to save the current attestation document yourself:

```bash
curl -sS -D - -o attestation.cbor -X POST http://localhost:9001/v1/attestation \
  -H "Content-Type: application/json" \
  -d '{"nonce": "your-base64-encoded-nonce-here"}'
```

**Security Note:** The aux API automatically sanitizes incoming attestation requests by removing `public_key` before forwarding them to the internal API. `nonce` and `user_data` are preserved, so external callers cannot override the enclave's default attestation key while still being able to provide freshness and caller-specific metadata.

## Check AWS Nitro enclave info

On the tested `app-node` host on March 14, 2026, `nitro-cli describe-enclaves`
run directly on the host returned `[]` even while `enclaver run` was active.
The working way to inspect the enclave was to resolve the running
`hn-fetcher-enclave:latest` container first and then execute `nitro-cli` inside
that container:

```bash
$ nitro-cli describe-enclaves
[]

$ cid=$(docker ps --filter ancestor=hn-fetcher-enclave:latest --format '{{.ID}}' | head -n1)
$ docker exec "$cid" /bin/nitro-cli describe-enclaves
[
  {
    "EnclaveName": "application",
    "EnclaveID": "i-07702f8ac844cd2d3-enc19ce9aaaedce5e2",
    "ProcessID": 14,
    "EnclaveCID": 16,
    "NumberOfCPUs": 2,
    "CPUIDs": [
      1,
      3
    ],
    "MemoryMiB": 1500,
    "State": "RUNNING",
    "Flags": "NONE",
    "Measurements": {
      "HashAlgorithm": "Sha384 { ... }",
      "PCR0": "9b86f0489c6c104a0f0952bf444dbabb447544acc573be5ec5ee40ecf8b80ad1deed98161fceddbb14e953b4502f66bd",
      "PCR1": "18b701b9e237424633a37b610308dcf15fb18a25fe12c80d9766b82661b3ecddae6825c6bc13b8fa254f72a87c177d40",
      "PCR2": "31cecadc8d56c371099dd7fbc5735ed2ab59c7dfd5d9be83b3a913e899121b116b8ebb7f086eb5085b46c3e54819df6d"
    }
  }
]
```
