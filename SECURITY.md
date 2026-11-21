# Security Policy

## Supported versions

Security fixes are applied to `main` and released in the latest `1.1.x` version. Please upgrade to the most recent release or build from `main` before reporting an issue.

| Version | Supported |
| --- | --- |
| 1.1.x (latest) | Yes |
| < 1.1 | No |

## Reporting a vulnerability

Do not open a public GitHub issue, pull request, or discussion for suspected security vulnerabilities.

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/jusso-dev/M365-Secure/security/advisories/new) (from the repository page: **Security** -> **Advisories** -> **Report a vulnerability**).

Please include as much of the following as you can:

- A clear description of the vulnerability and its potential security impact.
- The affected version or commit SHA, operating system, and authentication flow (`auth login` device code or `--client-secret` client credentials), where relevant.
- Minimal steps to reproduce or a proof of concept.
- Any suggested fix or mitigation.

Do not include real tenant IDs, subscription IDs, client secrets, access or refresh tokens, or customer assessment output in your report. Redact or replace sensitive values with synthetic placeholders before submitting.

## Expected response times

This project is maintained on a best-effort basis. We aim to meet the following timelines:

- **Initial acknowledgement**: within 3 business days of receiving a report.
- **Triage and assessment**: within 7 business days, confirming whether the report is accepted and in scope.
- **Fix and disclosure**: target within 30 days for high or critical severity issues and 90 days for moderate or low severity issues, depending on complexity.

We will coordinate public disclosure timing with the reporter inside the private GitHub security advisory before publishing details or releasing a patch.

## Scope

### In scope

- The `m365-assess` CLI and Rust source code in `src/`, including OAuth2 authentication and token exchange, macOS Keychain and on-disk token cache handling, accidental secret or credential leakage in logs or reports, report injection (such as HTML/XSS or CSV formula injection), and any behaviour that violates the tool's read-only assessment posture.
- Bundled control data, compliance mappings, and the Junction operation catalogue in `controls/` (for example, any write or mutating operation inadvertently added to `controls/junction-operations.txt` or `controls/junction-catalog.json`).
- Repository scripts in `scripts/` and CI/CD workflows in `.github/workflows/`.

### Out of scope

- Misconfigurations or security findings within a user's own Microsoft 365 tenant, Entra ID app registrations, or Azure subscriptions.
- Vulnerabilities in Microsoft Graph, Exchange Online, SharePoint Online, Teams, Intune, or other Microsoft cloud services; report those directly to the Microsoft Security Response Center (MSRC).
- Vulnerabilities in upstream dependencies (Rust crates, the Junction project at `jusso-dev/junction`, or third-party GitHub Actions) unless they are specifically exploitable through `M365-Secure`.
- Reports based solely on automated scanner output without demonstrated impact, or local denial-of-service issues requiring prior control of the user's machine or input files.
