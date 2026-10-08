# M365-Secure

`M365-Secure` is a Rust CLI that assesses the security configuration of a Microsoft 365 tenant. It signs in once, reads configuration from Microsoft Graph and the other Microsoft admin APIs it can reach, evaluates each setting against a control registry, and writes HTML, CSV and JSON reports with CIS, NIST CSF and other framework references on every finding.

The binary name is `m365-assess`.

- Device-code or client-credentials sign-in; Commercial, GCC High and DoD clouds
- Modules for identity, Exchange Online, Defender and compliance, SharePoint/Teams/Forms, Intune, hybrid identity, Azure, Power BI, Purview, licensing, inventory, SOC 2 evidence and licence value
- A control registry (`controls/registry.json` plus overlays in `controls/registry.d/`) that names every check and maps it to CIS Microsoft 365 v6 and v7, NIST SP 800-53, NIST CSF 2.0, ISO 27001, SOC 2, Essential Eight and more
- Findings that never silently disappear: a check that cannot run reports `Unknown` with the reason
- JSON output (schema 1.1) that other tools, including [crownguard](https://jusso-dev.github.io/crownguard/), can import

The full list of checks, with severity, automation status and CIS v7 / NIST CSF references, is in [docs/CHECKS.md](docs/CHECKS.md).

## What it does

1. Authenticates to Microsoft 365 and caches the token.
2. Collects tenant metadata: organisation, verified domains, subscribed SKUs and service plans.
3. Runs the selected modules. Each check produces a finding with a check id, status, severity, current value, expected value and remediation.
4. Attaches the registry's framework references and severity to every finding.
5. Maps findings onto the bundled compliance frameworks.
6. Writes the reports.

## Modules

Default modules (run by `scan full`):

| Module | Covers | Reads from |
|---|---|---|
| `identity` | Entra ID: MFA, authentication methods, Conditional Access, admin roles, PIM, guests, app registrations and enterprise apps, consent, password policy | Microsoft Graph |
| `licensing` | SKU inventory, allocation, premium tier detection | Microsoft Graph |
| `exchange` | Exchange Online: authentication, auditing, mail flow, forwarding, add-ins, calendar sharing; SPF, DKIM and DMARC DNS records | Exchange Online admin API, Graph, public DNS |
| `security` | Defender for Office 365, anti-spam/anti-malware/anti-phishing, Secure Score, DLP, sensitivity labels, audit log, alert policies | Graph (Secure Score, Purview, security APIs), Exchange Online admin API |
| `collaboration` | SharePoint and OneDrive sharing, Teams federation, meetings, apps and client settings, Forms | Graph, SharePoint Online admin, Teams admin |
| `intune` | Device compliance and configuration, enrolment, RBAC and scope tags, multi-admin approval, wipe audit, Defender for Endpoint posture | Graph, Defender for Endpoint API |
| `hybrid` | Entra Connect sync status and freshness | Microsoft Graph |
| `azure` | Azure subscriptions: RBAC, Defender for Cloud, Key Vault, storage exposure, backup, diagnostic settings, Sentinel | Azure Resource Manager through the Junction gateway |

Opt-in modules (`scan full --include ...` or `scan module <name>`):

| Module | Covers |
|---|---|
| `powerbi` | Power BI tenant settings (reported as Review items for admin-portal verification) |
| `purview` | Retention labels and event-based retention |
| `inventory` | Users, groups, sites and Teams counts |
| `soc2` | SOC 2 evidence mapping and manual-evidence prompts |
| `value` | Licence utilisation and security feature adoption |

`m365-assess scan list` prints the same list from the binary.

## Beyond Microsoft Graph

Graph does not expose everything the checks need. The tool signs in once and then exchanges its refresh token for tokens to the other APIs (`Resource` in `src/auth/mod.rs`). Whether that exchange succeeds depends on which application you signed in with:

| Resource | Used by | Default first-party client | Tenant-owned app registration (`--client-id`) |
|---|---|---|---|
| Microsoft Graph | all modules | yes | yes, with the Graph permissions below |
| Exchange Online admin API (`outlook.office365.com`) | `exchange`, `security` | yes | yes, with a delegated permission on the Office 365 Exchange Online API |
| Azure Resource Manager (`management.azure.com`) | `azure` | no | yes, with `user_impersonation` on Azure Service Management; the signed-in user needs Reader on the subscriptions (or the root management group) |
| SharePoint Online admin (`<tenant>-admin.sharepoint.com`) | `collaboration` | no | yes, with a delegated permission on the SharePoint API; the signed-in user needs SharePoint Administrator |
| Teams admin backend (`Skype.Policy`) | `collaboration` | no | yes; this API is undocumented and the checks degrade to `Unknown` when it refuses the app |
| Defender for Endpoint API (`api.securitycenter.microsoft.com`) | `intune` | no | yes, with the WindowsDefenderATP read permissions for the operations in `controls/junction-operations.txt` (machines, scores, advanced hunting, assessment export) |
| Power Platform API (`api.powerplatform.com`) | `azure` | no | yes |

The exact permission names depend on the API; the error returned when a token is refused names the resource, and `controls/junction-operations.txt` lists the operations called.

When a token for a resource cannot be obtained, every check that depends on it reports `Unknown` with the reason in `current_value` (for consent failures: "The signed-in app isn't consented for <resource>. Register an app with that API permission and pass `--client-id`, or skip the module."). Nothing is scored for those checks.

The Azure, Defender for Endpoint and Power Platform calls go through [Junction](https://github.com/jusso-dev/junction), a catalogue of Microsoft API operations generated from Microsoft's published API specifications, executed under a read-only policy. `controls/junction-catalog.json` is the subset of that catalogue this tool uses, listed by operation id in `controls/junction-operations.txt` and regenerated with:

```bash
scripts/junction-catalog.py /path/to/junction/checkout
```

Re-run it when adding operations or bumping the pinned Junction revision in `Cargo.toml`, and commit the result.

## Required Microsoft Graph permissions

These are the delegated scopes the binary requests (`GRAPH_SCOPES` in `src/auth/mod.rs`; `m365-assess info` prints the same list):

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
- `InformationProtectionPolicy.Read`
- `RecordsManagement.Read.All`
- `DeviceManagementServiceConfig.Read.All`
- `AccessReview.Read.All`
- `RoleManagementPolicy.Read.Directory`
- `RoleEligibilitySchedule.Read.Directory`
- `RoleAssignmentSchedule.Read.Directory`
- `OnPremDirectorySynchronization.Read.All`
- `CrossTenantInformation.ReadBasic.All`
- `Policy.Read.ConditionalAccess`
- `IdentityRiskyUser.Read.All`
- `Group.Read.All`
- `SecurityIdentitiesSensors.Read.All`
- `SecurityIdentitiesHealth.Read.All`
- `BackupRestore-Configuration.Read.All`
- `AuditLogsQuery.Read.All`
- `ThreatHunting.Read.All`

A check whose call is refused for lack of a permission reports `Unknown` and names the permission to grant.

## Authentication

### Device code flow (default)

```bash
m365-assess --tenant-id <tenant-guid> auth login
```

The tool prints a code and verification URL, opens the browser on macOS, and caches the token (macOS Keychain, or a file under `~/.m365-assess/` with restricted permissions). Without `--client-id` it uses a Microsoft first-party client id, which covers Graph and Exchange Online but none of the other resources above.

### Device code flow with your own app registration

```bash
m365-assess --tenant-id <tenant-guid> --client-id <app-id> auth login
```

Register an application in Entra ID, add the delegated Graph permissions above plus the API permissions for the resources you want assessed, enable the device code / public client flow, and grant admin consent.

### Client credentials flow

```bash
m365-assess --tenant-id <tenant-guid> --client-id <app-id> auth login --client-secret <secret>
```

Suitable for automation. Resource tokens other than Graph need the app consented for that resource; checks that are user-context only may return `Review` or `Unknown`.

### Status and logout

```bash
m365-assess --tenant-id <tenant-guid> auth status
m365-assess --tenant-id <tenant-guid> auth logout
```

### Environment variables

```bash
export M365_TENANT_ID="<tenant-guid>"
export M365_CLIENT_ID="<app-registration-client-id>"
```

### Clouds

`--cloud commercial|gcchigh|dod` switches the login, Graph and resource endpoints.

## Building and installing

```bash
cargo build --release          # ./target/release/m365-assess
cargo install --path .         # puts m365-assess on ~/.cargo/bin
```

The Junction crates are pulled from git at the revision pinned in `Cargo.toml`, so the first build needs network access.

## Quick start

```bash
cargo build --release
export M365_TENANT_ID="<tenant-guid>"
./target/release/m365-assess auth login
./target/release/m365-assess scan full
```

Reports land in `M365-Assessment/`:

- `_Assessment-Report_<primary-domain>.html`
- `_Assessment-Findings_<primary-domain>.csv`
- `_Assessment-Results_<primary-domain>.json`
- per-section CSV files (`NN-<Section>-<primary-domain>.csv`)

## Usage

Global options: `--tenant-id`, `--client-id`, `--cloud`, `-v`/`-vv`/`-vvv`, `--log-format text|json`.

```bash
m365-assess info                                   # version, frameworks, Graph scopes
m365-assess scan list                              # modules
m365-assess scan full                              # default modules
m365-assess scan full --format html,csv,json --output ./out/customer-a
m365-assess scan full --include inventory,soc2,powerbi,value
m365-assess scan full --quick                      # flag is parsed and stored; module support varies
m365-assess scan module identity                   # one module (also: exchange, security, collaboration,
                                                   #   intune, hybrid, azure, licensing, powerbi, purview,
                                                   #   inventory, soc2, value)
m365-assess report generate --input M365-Assessment/_Assessment-Results_<domain>.json \
    --output ./rerendered --format html,csv,json   # re-render from saved JSON
```

## Finding statuses

| Status | Meaning | Scored |
|---|---|---|
| `Pass` | Setting meets the expected value | yes |
| `Fail` | Setting does not meet the expected value | yes |
| `Warning` | Partially meets, or a weaker configuration is in place | no |
| `Review` | Evidence collected, but the pass condition depends on your context (for example a policy exists and its scope needs a human decision) | no |
| `Info` | Inventory or informational output | no |
| `Unknown` | The check could not run: missing permission or consent, unsupported API, licence gap, or API error. `current_value` carries the reason. Treat as unassessed, not failing | no |
| `NotLicensed` | The tenant lacks the service plan the control needs (`controls/licensing-overlay.json`) | no |

The score is `Pass / (Pass + Fail)`.

Severity comes from the registry's `impactRating.severity`, overridden by `controls/risk-severity.json` where that file has an entry, and defaults to `Medium`.

## Output files

Reports contain tenant names, domains and configuration details. `M365-Assessment/`, `*.html`, `*.csv` and `*.pdf` are ignored by git; keep tenant output out of version control.

### JSON report (schema 1.1)

```json
{
  "schema_version": "1.1",
  "tool": { "name": "m365-assess", "version": "1.0.0" },
  "summary": { "...": "tenant, counts, score" },
  "findings": [
    {
      "check_id": "CA-MFA-ALL-001",
      "category": "Identity",
      "section": "Conditional Access",
      "setting": "MFA Required for All Users",
      "description": "...",
      "status": "pass",
      "severity": "High",
      "current_value": "...",
      "expected_value": "...",
      "remediation": "...",
      "framework_mappings": {
        "cis": ["5.2.2.2"],
        "cis_v7": ["5.2.2.2"],
        "nist_csf": ["PR.AA-03"],
        "nist": ["IA-2", "IA-2(1)"],
        "soc2": ["CC6.1"],
        "essential_eight": ["ML1-P7"]
      },
      "timestamp": "..."
    }
  ],
  "compliance": [ "per-framework roll-ups" ]
}
```

`framework_mappings` keys: `cis` (CIS M365 v6), `cis_v7`, `nist` (SP 800-53), `nist_csf` (CSF 2.0), `iso27001`, `soc2`, `hipaa`, `pci_dss`, `cmmc`, `cisa_scuba`, `fedramp`, `essential_eight`, `mitre_attack`, and `other` for any further registry key (`nis2`, `iso-27017`, `gdpr`, `stig`). Empty lists are omitted. Schema 1.0 files (no `schema_version`, empty `framework_mappings`) still load in `report generate`.

### CSV

One row per finding with the finding fields plus `CIS M365 v7`, `CIS M365 v6`, `NIST CSF 2.0` and `Essential Eight` columns.

### HTML

Summary cards (including Unknown and Not Licensed counts), severity breakdown, findings grouped by section with their framework references, framework compliance cards, filtering, print layout, light/dark theme.

## Use with crownguard

[crownguard](https://jusso-dev.github.io/crownguard/) is a questionnaire-driven Microsoft 365 security review that runs in the browser. Import `_Assessment-Results_<domain>.json` there to pre-fill answers: its content pack maps each question to one or more check ids from this tool, and the statuses decide the suggestion (all mapped checks `pass` = Yes, all `fail` = No, anything mixed or `warning` = Partial). `review`, `info`, `unknown` and `notlicensed` findings are shown as evidence but do not pre-fill. The tenant's licence tier is suggested from `summary.tenant.license_skus`. Every pre-filled answer shows the finding it came from and can be changed; questions that need a human judgement stay open. The file is read locally and is not uploaded anywhere.

## Compliance frameworks

Framework definitions live in `controls/frameworks/`. Loaded by the binary:

CIS Microsoft 365 Foundations v6 and v7, CIS Controls v8, NIST CSF 2.0, NIST SP 800-53 Rev. 5, PCI DSS v4, ISO 27001:2022, SOC 2 TSC, HIPAA, CMMC 2.0, FedRAMP, CISA SCuBA, Essential Eight, MITRE ATT&CK, Entra ID STIG, DISA STIG.

CIS v7 numbers were taken over from v6 for every recommendation whose number and title are unchanged; the registry has no entries yet for recommendations new in v7 (application credential policies 5.1.5.3–5.1.5.6, DLP for Copilot 3.2.3, authentication transfer 5.2.2.17, AIR 2.4.5, named locations and token protection 5.2.2.13–5.2.2.16).

## Controls and metadata

- `controls/registry.json` — the check registry: id, name, category, collector, `hasAutomatedCheck`, licensing, `impactRating.severity`, and `frameworks.<key>.controlId` for each framework.
- `controls/registry.d/*.json` — overlays in the same `{ "checks": [...] }` shape, applied in file-name order; an overlay entry replaces the base entry with the same id. Modules add their new checks here.
- `controls/risk-severity.json` — severity overrides, only where they differ from the registry.
- `controls/licensing-overlay.json` — service plans a check requires (drives `NotLicensed`).
- `controls/frameworks/*.json` — framework metadata.
- `controls/junction-operations.txt`, `controls/junction-catalog.json` — the Junction operations the binary embeds.
- `controls/role-tiers.json`, `controls/tier0-permissions.json`, `controls/sku-feature-map.json`, `controls/mitre-technique-map.json` — supporting lookups.
- `docs/CHECKS.md` — generated table of every check (`scripts/checks-table.py`).

`tests/registry_consistency.rs` fails the build when a module emits a check id the registry does not define, or when a registry check marked automated is never emitted.

## Repository layout

```text
.
├── Cargo.toml
├── controls/              # registry, overlays, frameworks, Junction catalogue
├── docs/CHECKS.md         # generated check catalogue
├── scripts/               # checks-table.py, junction-catalog.py
├── src/
│   ├── main.rs, cli.rs
│   ├── auth/              # sign-in, token cache, resource token exchange
│   ├── graph/             # Graph client: paging, retry, resource API calls
│   ├── clients/           # SharePoint admin (CSOM) and Teams admin clients
│   ├── junction.rs        # Junction gateway for ARM, Defender for Endpoint, Power Platform
│   ├── assessment/        # findings, registry loading, severity, engine
│   ├── compliance/        # framework loading and mapping
│   ├── modules/           # one file per module
│   ├── report/            # HTML, CSV, JSON
│   └── output/
└── tests/                 # registry consistency test
```

## Development

```bash
cargo fmt --all --check
cargo build --locked
cargo test --locked
cargo clippy --locked -- -D warnings
python3 -m json.tool controls/registry.json > /dev/null
scripts/checks-table.py          # regenerate docs/CHECKS.md after registry changes
```

The same steps run in CI (`.github/workflows/ci.yml`).

## Platform notes

Token storage prefers the macOS Keychain and device-code login opens the browser with `open`; both fall back gracefully elsewhere, but Linux and Windows have not been exercised as thoroughly.

## License

MIT. See `Cargo.toml`.
