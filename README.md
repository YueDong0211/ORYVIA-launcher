# ORYVIA launcher

The ORYVIA launcher imports an authorized ORYVIA Unix workstation package and
connects it to its existing environment setup, local start, stop and environment
check commands. Version **2026.10.24.3** supports the ORYVIA Unix application
version **2026.10.24.3**.

This repository provides the standalone MIT-licensed launcher. The ORYVIA
scientific application is proprietary and supplied separately under its own
authorization. Its analysis source, installation archives, models and research
data are not distributed here. Installing this launcher alone does not install
the association or downstream analysis engine.

## About the ORYVIA workstation

ORYVIA connects genotype–phenotype input validation, association modelling,
effect estimation, candidate review and scientific plotting in a local browser
workspace. GLM, MLM, native FarmCPU and the ORYVIA association method are
separate model choices. Posterior-effect methods, independent effect checks,
prediction calibration and data-specific causal analyses follow the association
step when their required inputs are available. Posterior associations and
predictive intervals retain their own interpretation; a causal analysis uses
its stated exposure/outcome design and identifying assumptions.

Users supply and name their own inputs, select the reference assembly used by
their data, choose an association model and then add relevant downstream
analyses. The workstation exports results, plot source data and settings.
Optional native R tools remain separate environment profiles. The authorized
application includes its detailed method, input and cluster instructions.

Application access is arranged with the software owner. The public issue
tracker for this launcher can be used to request distribution information; no
private installation archive should be attached to a public issue.

## Installation

Use native Linux or macOS with Bash and Python 3.12 or 3.13. This launcher uses
only Python's standard library at runtime. Install from this source directory:

```sh
python -m pip install .
oryvia --version
```

The Bioconda submission is being prepared. A Bioconda installation command will
be added when a reviewed channel package is available.

## Register an authorized application

Obtain the **Unix package and its SHA-256 receipt** through the software owner's
authorized distribution channel. Use the checksum from that receipt; computing
a checksum for an untrusted archive does not establish who supplied it.

```sh
oryvia inspect-archive --archive /path/to/authorized-package.zip \
  --sha256 YOUR_64_CHARACTER_DELIVERY_SHA256

oryvia register --archive /path/to/authorized-package.zip \
  --sha256 YOUR_64_CHARACTER_DELIVERY_SHA256 \
  --workspace "$HOME/ORYVIA-2026.10.24.3" --accept-authorized-package
```

The workspace must not already exist and its parent must exist. Registration
creates `application/` and a small registration receipt inside that workspace.
It leaves the original archive in place. It does not execute application code,
install dependencies, contact a server or load user data.

Registration checks the complete archive checksum, delivery version and Unix
platform, and the size and SHA-256 of every manifested file. Unexpected files,
missing files, traversal paths, links, special files, duplicate names and case
aliases are rejected. Import limits are 20,000 payload files and 8 GiB expanded
content. Checksums detect content changes; they are not digital signatures.
Authorization to use the scientific application remains governed by its own
terms.

## Prepare and use the workstation

Environment installation is an explicit step. For the core Python environment:

```sh
oryvia setup --workspace "$HOME/ORYVIA-2026.10.24.3" -- --python
oryvia check --workspace "$HOME/ORYVIA-2026.10.24.3"
oryvia start --workspace "$HOME/ORYVIA-2026.10.24.3"
```

The application opens its local workstation. Submit your own genotype and
phenotype files through its standard input workflow. This launcher includes no
preloaded research dataset. To stop that workspace:

```sh
oryvia stop --workspace "$HOME/ORYVIA-2026.10.24.3"
```

`setup`, `start`, `stop` and `check` invoke the registered package's `SETUP.sh`,
`START.sh`, `STOP.sh` and `CHECK_ENVIRONMENT.sh`. Arguments following `--` are
passed as literal process arguments. The launcher's Python creates the core
environment during setup; normal application startup uses the application's
own `.venv`. Startup never installs dependencies.

Optional R methods remain in the authorized application. After installing a
native R version compatible with that application's lock files, select it with
`HAP_RSCRIPT` and explicitly request the relevant profile:

```sh
oryvia setup --workspace "$HOME/ORYVIA-2026.10.24.3" -- --r
oryvia setup --workspace "$HOME/ORYVIA-2026.10.24.3" -- --bayesian
oryvia setup --workspace "$HOME/ORYVIA-2026.10.24.3" -- --cause
```

The application documents these profiles, package locks and system toolchains.
This launcher bundles no R, Qwen, language model or scientific Python packages.
For a cluster, use the authorized application's batch/cluster interface after
environment preparation; the launcher does not select scheduler resources or
silently submit jobs.

## Inspect, verify and update

```sh
oryvia info --workspace "$HOME/ORYVIA-2026.10.24.3"
oryvia verify --workspace "$HOME/ORYVIA-2026.10.24.3"
```

Every executed application command first verifies all originally shipped
members against the registered manifest. User-created results and the prepared
environment may coexist with those files. Modified shipped files are reported
and execution stops. To adopt another authorized delivery, register it in a
new workspace, then transfer user inputs/results deliberately; registration
does not overwrite an existing installation or user history.

The current launcher supports the delivery manifest
`ORYVIA_PRIVATE_DELIVERY_MANIFEST_V1` for application version 2026.10.24.3.
Changing the launcher does not change the proprietary application's license.

## Tests and license

```sh
python -m unittest discover -s tests -v
```

Tests construct small synthetic archives and inert entry scripts. They cover
checksum/manifest integrity, unsafe paths and links, overwrite protection,
command forwarding and the public CLI without using ORYVIA analysis source or
research data. The [MIT license](LICENSE) covers this launcher, its tests and
documentation only.
