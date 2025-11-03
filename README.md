<img src="docs/img/enclaver-logo-color.png" width="350" />

Enclaver is an open source toolkit created to enable easy adoption of software enclaves, for new and existing backend software.

This is a Sparsity edition of Enclaver. See [here](https://github.com/enclaver-io/enclaver) for original project details.

## Installation

Run this command to install the latest version of the `enclaver` CLI tool:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/sparsity-xyz/enclaver/refs/heads/sparsity/install.sh)"
```

## Architecture

Read the [architecture doc](https://enclaver.io/docs/0.x/architecture/) for the full details. Enclaver consists of 3 interrelated pieces of software: 

 - `enclaver` CLI for build and run
 - “Outer Proxy” + Enclave Supervisor
 - “Inner Proxy” + Process Supervisor

<img src="docs/img/diagram-enclaver-components.svg" width="800" />

