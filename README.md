# M365-Secure

`M365-Secure` is a Rust-based Microsoft 365 security assessment CLI. It connects to Microsoft Graph, evaluates tenant configuration across core Microsoft 365 security domains, and produces operator-friendly reports in HTML, CSV, and JSON.

This repository is a local, native implementation of an M365 assessment workflow with:

- Microsoft 365 / Entra ID authentication using device code or client credentials
- Assessment modules for identity, Exchange, security, collaboration, Intune, licensing, hybrid, Purview, Power BI, inventory, SOC 2, and value opportunity analysis
- A bundled control registry with severity metadata and framework mappings
- Report generation for executive review and analyst follow-up
- Multi-cloud targeting for Commercial, GCC High, and DoD Microsoft tenants

The binary name is `m365-assess`.

## What It Does

At a high level, the tool:

1. Authenticates to Microsoft 365.
2. Collects tenant metadata such as organization details, verified domains, and subscribed SKUs.
3. Runs one or more assessment modules against Microsoft Graph and selected Microsoft 365 admin APIs.
4. Normalizes the results into findings with:
   - a check ID
   - status
   - severity
   - current value
   - expected value
   - remediation guidance
5. Maps findings to bundled compliance frameworks.
6. Generates reports for security, engineering, audit, and consulting workflows.

The repository currently includes `245` registry-backed checks in `controls/registry.json`, plus severity overrides, licensing overlays, and framework metadata under `controls/`.

## Assessment Coverage

### Default modules

These are run by `scan full` unless you explicitly target a single module:

- `identity` - Entra ID / Azure AD posture, MFA, Conditional Access, admins, guest access, app exposure, PIM, password-related controls
- `licensing` - SKU visibility, allocation analysis, service plan awareness
- `exchange` - Exchange Online posture, authentication, auditing, mail flow and DNS-related checks, with Secure Score and EXO REST/API fallbacks where available
- `security` - Microsoft Defender, Secure Score, anti-phishing, anti-spam, DLP/compliance-adjacent checks exposed via Graph and Secure Score
- `collaboration` - SharePoint, Teams, Forms, guest sharing and collaboration settings
- `intune` - Device management, device compliance, enrollment and management posture
- `hybrid` - Entra Connect / hybrid identity signals

### Opt-in modules

These are available but not included in a default full scan:

- `powerbi` - Power BI tenant security posture
- `purview` - Data governance / retention / Purview-aligned controls
- `inventory` - Detailed object inventory for deeper environment analysis
- `soc2` - SOC 2 oriented readiness and evidence mapping
- `value` - License utilization and feature adoption / opportunity analysis

## Compliance Framework Mapping

The tool ships with framework definitions in `controls/frameworks/` and maps findings into reportable compliance views.

Framework files currently present in the repo include:

- CIS Microsoft 365 Foundations v6
- CIS Controls v8
- NIST CSF
- NIST SP 800-53 Rev. 5
- PCI DSS v4
- ISO 27001
- SOC 2 TSC
- HIPAA
- CMMC
- FedRAMP
- CISA SCuBA
- Essential Eight
- MITRE ATT&CK
- Entra ID STIG
- DISA STIG

The `info` command also advertises framework support from the compiled binary.

## Repository Layout

```text
.
├── Cargo.toml
├── controls/
│   ├── registry.json
│   ├── risk-severity.json
│   ├── licensing-overlay.json
│   ├── sku-feature-map.json
│   ├── role-tiers.json
│   ├── tier0-permissions.json
│   ├── mitre-technique-map.json
│   └── frameworks/
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── auth/
│   ├── graph/
│   ├── assessment/
│   ├── compliance/
│   ├── modules/
│   ├── report/
│   └── output/
└── target/              # local build output, ignored by git
```

### Important directories

- `src/auth/` - login flows, token refresh, token caching, cloud environment handling
- `src/graph/` - Graph API client with pagination, retry, and request concurrency limiting
- `src/assessment/` - finding model, registry loading, severity handling, assessment engine
- `src/modules/` - individual assessment modules
- `src/compliance/` - framework loading and finding-to-framework mapping
- `src/report/` - HTML, CSV, and JSON report generation
- `controls/` - assessment metadata and compliance mapping source files
- `M365-Assessment/` - default generated report directory, intentionally ignored by git

## Prerequisites

### Runtime / build prerequisites

- Rust stable toolchain
- Cargo
- Access to a Microsoft 365 tenant you are authorized to assess
- A Microsoft Entra application registration if you do not want to use the built-in default client ID

### Platform notes

- The project is clearly macOS-first:
  - token storage prefers macOS Keychain via `security-framework`
  - device code login attempts to open the browser with `open`
- There is also a file-based token cache fallback under `~/.m365-assess/` with restricted permissions on Unix systems

If you plan to run this on Linux or Windows, verify build and auth behavior in your environment. The repository includes cross-platform Rust dependencies, but the default experience is tuned for macOS.

## Building

### Debug build

```bash
cargo build
```

### Release build

```bash
cargo build --release
```

The release binary will be at:

```bash
./target/release/m365-assess
```

You can also run the tool directly through Cargo:

```bash
cargo run -- <command>
```

## Installing Locally

Install the CLI from this checkout:

```bash
cargo install --path .
```

After installation, make sure Cargo's binary directory is on your `PATH`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Then run:

```bash
m365-assess info
```

## Authentication

The CLI supports two authentication approaches:

- Device code flow
- Client credentials flow

### Device code flow

This is the default and the easiest way to get started interactively.

```bash
m365-assess --tenant-id <tenant-guid> auth login
```

Behavior:

- The tool requests a device code from the Microsoft login endpoint for the selected cloud
- It prints the code and verification URL
- On macOS, it attempts to open the browser automatically
- On success, it caches the token for reuse

### Client credentials flow

Use this for non-interactive execution when you have an app registration and secret.

```bash
m365-assess --tenant-id <tenant-guid> --client-id <app-id> auth login --client-secret <secret>
```

Notes:

- This flow is suitable for automation, but not every API path behaves identically under app-only auth
- Some Exchange Online and user-context-sensitive checks may still degrade to warnings or review-required results depending on available API access

### Authentication status

```bash
m365-assess --tenant-id <tenant-guid> auth status
```

### Logout

```bash
m365-assess --tenant-id <tenant-guid> auth logout
```

## Environment Variables

The CLI supports global environment variables through Clap:

```bash
export M365_TENANT_ID="<tenant-guid>"
export M365_CLIENT_ID="<app-registration-client-id>"
```

After that, commands can be shorter:

```bash
m365-assess auth login
m365-assess scan full
```

## Cloud Environments

The `--cloud` global option supports:

- `commercial`
- `gcchigh`
- `dod`

Examples:

```bash
m365-assess --tenant-id <tenant-guid> --cloud commercial scan full
m365-assess --tenant-id <tenant-guid> --cloud gcchigh scan full
m365-assess --tenant-id <tenant-guid> --cloud dod scan full
```

Internally, the tool switches both login endpoints and Graph resource endpoints based on the selected cloud.

## Required Microsoft Graph Permissions

The binary exposes the following required Graph scopes for full assessments:

- `Organization.Read.All`
- `Domain.Read.All`
- `User.Read.All`
- `AuditLog.Read.All`
- `UserAuthenticationMethod.Read.All`
- `RoleManagement.Read.Directory`
- `Policy.Read.All`
- `Application.Read.All`
- `Directory.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementRBAC.Read.All`
- `DeviceManagementApps.Read.All`
- `SecurityEvents.Read.All`
- `SharePointTenantSettings.Read.All`
- `TeamSettings.Read.All`
- `TeamworkAppSettings.Read.All`
- `MailboxSettings.Read`
- `Team.ReadBasic.All`
- `TeamMember.Read.All`
- `Channel.ReadBasic.All`
- `Reports.Read.All`
- `Sites.Read.All`
- `SecurityAlert.Read.All`

In practice, you should treat this as the minimum Graph permission set for broad assessment coverage. Some checks may still require additional admin roles or service-specific API support.

## App Registration Setup

For a full assessment, use an Entra app registration with the Graph API permissions above and tenant admin consent granted.

Recommended setup:

1. Create an app registration in Microsoft Entra ID.
2. Add the delegated Microsoft Graph permissions listed above for interactive device-code use.
3. Grant admin consent for the tenant.
4. Export the tenant and client IDs before running the CLI:

```bash
export M365_TENANT_ID="<tenant-guid>"
export M365_CLIENT_ID="<app-registration-client-id>"
```

For automation, create a client secret and use the client credentials login command. Store secrets in your shell, CI secret store, or password manager; do not commit them to this repository.

## Quick Start

### 1. Build the project

```bash
cargo build --release
```

### 2. Set your tenant ID

```bash
export M365_TENANT_ID="<tenant-guid>"
```

### 3. Authenticate

```bash
./target/release/m365-assess auth login
```

### 4. Run a full assessment

```bash
./target/release/m365-assess scan full
```

### 5. Open the generated report

Look in the default output directory:

```text
M365-Assessment/
```

Typical outputs:

- `_Assessment-Report_<primary-domain>.html`
- `_Assessment-Findings_<primary-domain>.csv`
- `_Assessment-Results_<primary-domain>.json`
- per-section CSV files such as `05-Conditional-Access-<primary-domain>.csv`

## Usage

### Global options

These apply across commands:

- `--tenant-id <GUID>` - target Entra tenant ID
- `--client-id <GUID>` - app registration client ID
- `--cloud <commercial|gcchigh|dod>` - target Microsoft cloud
- `-v`, `-vv`, `-vvv` - increase logging verbosity
- `--log-format <text|json>` - structured logging output

### Show tool information

```bash
m365-assess info
```

This prints version, platform/runtime details, framework support, and the compiled list of required permissions.

### List available modules

```bash
m365-assess scan list
```

### Run a full scan

```bash
m365-assess scan full
```

With explicit output formats:

```bash
m365-assess scan full --format html,csv,json
```

With a custom output directory:

```bash
m365-assess scan full --output ./out/customer-a
```

Quick scan mode:

```bash
m365-assess scan full --quick
```

Important note: `--quick` is exposed in the CLI and stored in scan configuration, but you should verify the current module implementations before assuming every module actively short-circuits to critical/high-only logic.

### Run a full scan with opt-in modules

```bash
m365-assess scan full --include inventory,soc2
```

```bash
m365-assess scan full --include inventory,soc2,powerbi,value
```

### Run a single module

```bash
m365-assess scan module identity
```

Other examples:

```bash
m365-assess scan module exchange
m365-assess scan module security
m365-assess scan module collaboration
m365-assess scan module intune
m365-assess scan module licensing
m365-assess scan module hybrid
m365-assess scan module powerbi
m365-assess scan module purview
m365-assess scan module inventory
m365-assess scan module soc2
m365-assess scan module value
```

### Regenerate reports from saved JSON

If you already have a JSON assessment result, you can generate reports again without re-running the scan logic:

```bash
m365-assess report generate \
  --input M365-Assessment/_Assessment-Results_<primary-domain>.json \
  --output M365-Assessment \
  --format html
```

You can also generate multiple formats:

```bash
m365-assess report generate \
  --input M365-Assessment/_Assessment-Results_<primary-domain>.json \
  --output ./rerendered \
  --format html,csv,json
```

## Output Files

Generated reports frequently contain tenant names, domains, user metadata, security findings, and remediation details. They are operational artifacts, not source code.

The default `M365-Assessment/` output directory is ignored by git, and `.gitignore` also excludes generated `.html`, `.pdf`, and `.csv` files so assessment deliverables are not accidentally committed. Keep customer or tenant-specific outputs outside version control unless you have explicitly sanitized them.

### HTML report

The HTML report is designed for executive and analyst review. It includes:

- tenant summary
- security score
- pass/fail/warning/review counts
- severity breakdown
- grouped findings by section
- framework compliance cards
- client-side filtering
- printable layout
- light/dark theme toggle

Filename pattern:

```text
_Assessment-Report_<primary-domain>.html
```

### CSV reports

The main CSV includes one row per finding with:

- check ID
- category
- section
- setting
- description
- status
- severity
- current value
- expected value
- remediation
- timestamp

Filename pattern:

```text
_Assessment-Findings_<primary-domain>.csv
```

The tool also writes per-section CSV files using numbered prefixes such as:

- `02-Identity-<domain>.csv`
- `05-Conditional-Access-<domain>.csv`
- `10-Mail-Flow-<domain>.csv`
- `20-SharePoint-<domain>.csv`
- `21-Teams-<domain>.csv`
- `22-Power-BI-<domain>.csv`

Unmapped or custom sections fall back to a `99-...` prefix.

### JSON report

The JSON output is the canonical machine-readable result. It contains:

- `summary`
- `findings`
- `compliance`

Filename pattern:

```text
_Assessment-Results_<primary-domain>.json
```

This file is what powers `report generate`.

## How Findings Are Scored

Each finding is normalized into:

- a status such as `Pass`, `Fail`, `Warning`, `Review`, `Info`, or licensing/unknown states
- a severity derived from `controls/risk-severity.json` when available
- a remediation statement intended for operator follow-up

The overall score reported by the engine is calculated from scoreable findings only:

- `Pass`
- `Fail`

Warnings, review-required items, informational results, and unsupported/licensing-driven outcomes do not directly contribute to the numeric score.

## Controls and Metadata

The assessment logic is split between Rust code and registry-backed metadata.

### `controls/registry.json`

Defines:

- check IDs
- check names
- categories
- collector/source labels
- whether the check is automated
- licensing metadata

### `controls/risk-severity.json`

Overrides severity by check ID.

### `controls/frameworks/*.json`

Provides framework definitions used for compliance mapping and reporting.

### Other control metadata

The repository also includes metadata for:

- license/service plan overlays
- role tiering
- tier-0 style permissions
- SKU feature mapping
- MITRE technique mapping

## Operational Behavior and Design Notes

### Tenant discovery

At the start of a scan, the engine collects:

- organization information
- verified domains
- primary/default domain
- subscribed SKUs and service plans

This tenant context is then reused by modules that need licensing or domain awareness.

### Graph client behavior

The Graph client includes:

- request timeout handling
- pagination support
- simple request retry pathways
- capped request concurrency through a semaphore

This is useful when scanning large tenants or endpoints that return paged collections.

### Exchange behavior

Exchange assessment logic is mixed-mode:

- Microsoft Graph where available
- Exchange admin REST/API invocation where possible
- Secure Score fallback logic for partial verification

If a setting cannot be verified automatically, the module may emit `Review` findings rather than a hard pass/fail. That is intentional and preferable to inventing a result.

### Token storage

Auth tokens are cached per tenant.

Storage order:

1. macOS Keychain when available
2. `~/.m365-assess/token_<tenant>.json` fallback

The Unix fallback file is written with restricted permissions where supported.

## Example Workflows

### Consultant / assessment workflow

```bash
export M365_TENANT_ID="<tenant-guid>"
export M365_CLIENT_ID="<app-id>"

m365-assess auth login
m365-assess scan full --include inventory,soc2 --output ./deliverables/customer-01
```

Deliverables to review:

- HTML report for presentation
- main CSV for detailed remediation backlog
- section CSVs for domain-specific workstreams
- JSON for archival or downstream automation

### Focused identity review

```bash
m365-assess scan module identity --output ./identity-review --format html,csv,json
```

### Regenerate presentation-ready HTML later

```bash
m365-assess report generate \
  --input ./deliverables/customer-01/_Assessment-Results_contoso.com.json \
  --output ./deliverables/customer-01 \
  --format html
```

## Development

### Run from source

```bash
cargo run -- scan list
```

```bash
cargo run -- --tenant-id <tenant-guid> auth status
```

### Format

```bash
cargo fmt
```

### Lint

```bash
cargo clippy
```

### Test

If/when tests are added:

```bash
cargo test
```

At the time of writing, the repository structure is heavily implementation-oriented and may not yet include broad automated test coverage for every module path.

## Known Limitations

- Some checks depend on Microsoft Graph endpoints that may vary by license tier, tenant configuration, or API availability.
- Some Exchange Online controls cannot be fully verified through currently implemented REST-accessible paths and may fall back to `Review`.
- The `--quick` flag exists in the CLI and config model, but you should confirm current module-level enforcement before relying on it for reduced-scope production runs.
- macOS has the most polished auth/token-cache experience.
- A successful login does not guarantee that every check will return data; missing role assignments, unsupported APIs, or unavailable features can still produce warnings or review items.

## Troubleshooting

### `--tenant-id is required`

Set it explicitly or export `M365_TENANT_ID`.

```bash
export M365_TENANT_ID="<tenant-guid>"
```

### Authentication succeeds but checks fail

Common causes:

- the signed-in user lacks the required admin roles
- the app registration lacks consent for required Graph scopes
- a module is querying a feature not licensed in the tenant
- a service-specific API path is unavailable in the selected cloud

### `Controls directory not found`

The binary expects a `controls/` directory with `registry.json` available relative to the working directory or executable path.

If you distribute the binary separately, include the `controls/` folder alongside it or in one of the expected relative locations.

### Report regeneration fails

The `report generate` command expects a JSON input file that contains:

- `summary`
- `findings`
- optionally `compliance`

Use a file originally emitted by this tool's JSON report writer.

## License

This project is licensed under the MIT License according to `Cargo.toml`.
