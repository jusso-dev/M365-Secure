use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

use crate::assessment::engine::AssessmentSummary;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::severity::Severity;
use crate::compliance::mapping::ComplianceResult;

pub fn generate_html_report(
    path: &Path,
    summary: &AssessmentSummary,
    findings: &[Finding],
    compliance_results: &[ComplianceResult],
) -> Result<()> {
    let html = build_html(summary, findings, compliance_results);
    std::fs::write(path, html)?;
    tracing::info!("HTML report written to {}", path.display());
    Ok(())
}

/// Sections in the order operators expect to read them; anything else follows alphabetically.
const SECTION_ORDER: &[&str] = &[
    "Identity",
    "Authentication Methods",
    "Conditional Access",
    "Privileged Access",
    "Entra Security",
    "Enterprise Apps",
    "App Registrations",
    "Password Policy",
    "Guest Access",
    "Devices",
    "Licensing",
    "Exchange",
    "Mail Flow",
    "DNS",
    "Defender",
    "Compliance",
    "Purview",
    "SharePoint",
    "Teams",
    "Forms",
    "Power BI",
    "Intune",
    "Defender for Endpoint",
    "Hybrid",
    "Azure",
    "Logging",
    "Backup",
    "SOC 2",
    "Inventory",
    "Value Opportunity",
];

fn count(findings: &[&Finding], status: FindingStatus) -> usize {
    findings.iter().filter(|f| f.status == status).count()
}

fn framework_refs(f: &Finding) -> String {
    let m = &f.framework_mappings;
    let mut parts = Vec::new();
    let push = |parts: &mut Vec<String>, label: &str, refs: &[String]| {
        if !refs.is_empty() {
            parts.push(format!(
                "<span class=\"fw\"><b>{}</b> {}</span>",
                label,
                html_escape(&refs.join(", "))
            ));
        }
    };
    push(&mut parts, "CIS v7", &m.cis_v7);
    if m.cis_v7.is_empty() {
        push(&mut parts, "CIS v6", &m.cis);
    }
    push(&mut parts, "CSF 2.0", &m.nist_csf);
    push(&mut parts, "E8", &m.essential_eight);
    push(&mut parts, "800-53", &m.nist);
    parts.join(" ")
}

fn build_html(
    summary: &AssessmentSummary,
    findings: &[Finding],
    compliance_results: &[ComplianceResult],
) -> String {
    let all: Vec<&Finding> = findings.iter().collect();
    let pass = count(&all, FindingStatus::Pass);
    let fail = count(&all, FindingStatus::Fail);
    let warn = count(&all, FindingStatus::Warning);
    let review = count(&all, FindingStatus::Review);
    let unknown = count(&all, FindingStatus::Unknown);
    let not_licensed = count(&all, FindingStatus::NotLicensed);

    let failing_by_severity = |sev: Severity| {
        findings
            .iter()
            .filter(|f| f.severity == sev && f.status == FindingStatus::Fail)
            .count()
    };
    let critical = failing_by_severity(Severity::Critical);
    let high = failing_by_severity(Severity::High);
    let medium = failing_by_severity(Severity::Medium);
    let low = failing_by_severity(Severity::Low);

    let mut by_section: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_section.entry(f.section.clone()).or_default().push(f);
    }
    let mut ordered: Vec<(&String, &Vec<&Finding>)> = Vec::new();
    for name in SECTION_ORDER {
        if let Some((k, v)) = by_section.get_key_value(*name) {
            ordered.push((k, v));
        }
    }
    for (k, v) in &by_section {
        if !SECTION_ORDER.contains(&k.as_str()) {
            ordered.push((k, v));
        }
    }

    let mut html = String::with_capacity(200_000);
    html.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>M365 Security Assessment - {tenant}</title>
<style>
:root {{
    --bg: #fbfbfd; --bg-card: #ffffff; --text: #1c2333; --text-muted: #5b6478; --border: #e2e5eb;
    --pass: #1d6b3f; --fail: #b3261e; --warn: #8a5a00; --review: #0b5d8c; --info: #5b6478; --unknown: #6b4fbb;
    --critical: #b3261e; --high: #c2410c; --medium: #8a5a00; --low: #4a5568; --accent: #1f4fd8; --accent-soft: #eaf0ff;
}}
[data-theme="dark"] {{
    --bg: #0f1420; --bg-card: #161c2b; --text: #e8ebf2; --text-muted: #a2abbf; --border: #283044;
    --pass: #5ed39a; --fail: #ff7b72; --warn: #f0c247; --review: #6cc3ff; --unknown: #b8a2ff; --accent: #7aa2ff; --accent-soft: #1b2744;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
html, body {{ overflow-x: clip; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; font-size: 15px; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.86em; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 0 20px; }}
header {{ background: var(--bg-card); border-bottom: 1px solid var(--border); padding: 22px 0; margin-bottom: 28px; }}
header .container {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; }}
h1 {{ font-size: 1.5em; font-weight: 700; letter-spacing: -0.01em; }}
h2 {{ font-size: 1.15em; font-weight: 600; margin-bottom: 12px; }}
.subtitle {{ color: var(--text-muted); margin-top: 4px; font-size: 0.95em; }}
.eyebrow {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.72em; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text-muted); }}
.theme-toggle {{ background: transparent; border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }}
.stat-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; }}
.stat-value {{ font-size: 1.9em; font-weight: 700; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }}
.stat-label {{ color: var(--text-muted); font-size: 0.82em; margin-top: 2px; }}
.stat-hint {{ color: var(--text-muted); font-size: 0.75em; margin-top: 6px; }}
.score-card {{ border-color: var(--accent); background: var(--accent-soft); }}
.score-card .stat-value {{ color: var(--accent); }}
.severity-bar {{ display: flex; gap: 8px; margin-bottom: 24px; flex-wrap: wrap; align-items: center; color: var(--text-muted); font-size: 0.9em; }}
.severity-badge {{ display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 6px; font-size: 0.85em; font-weight: 600; border: 1px solid var(--border); }}
.severity-critical {{ color: var(--critical); }} .severity-high {{ color: var(--high); }} .severity-medium {{ color: var(--medium); }} .severity-low {{ color: var(--low); }} .severity-info {{ color: var(--info); }}
.section {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 16px; overflow: hidden; }}
.section-header {{ padding: 14px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; gap: 12px; font-weight: 600; border-bottom: 1px solid var(--border); flex-wrap: wrap; }}
.section-header:hover {{ background: var(--accent-soft); }}
.section-stats {{ display: flex; gap: 8px; font-size: 0.8em; flex-wrap: wrap; }}
.section-stats span {{ padding: 2px 9px; border-radius: 6px; font-weight: 600; border: 1px solid var(--border); }}
.section.collapsed .section-body {{ display: none; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.88em; }}
th {{ background: var(--bg); padding: 9px 14px; text-align: left; font-weight: 600; border-bottom: 1px solid var(--border); font-size: 0.78em; letter-spacing: 0.04em; text-transform: uppercase; color: var(--text-muted); }}
td {{ padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }}
tr:last-child td {{ border-bottom: none; }}
.status {{ font-weight: 600; white-space: nowrap; }}
.status-pass {{ color: var(--pass); }} .status-fail {{ color: var(--fail); }} .status-warning {{ color: var(--warn); }}
.status-review {{ color: var(--review); }} .status-info {{ color: var(--info); }} .status-unknown {{ color: var(--unknown); }}
.status-notlicensed {{ color: var(--text-muted); font-style: italic; }}
.filter-bar {{ display: flex; gap: 6px; margin-bottom: 18px; flex-wrap: wrap; }}
.filter-btn {{ padding: 5px 13px; border: 1px solid var(--border); border-radius: 6px; cursor: pointer; background: var(--bg-card); color: var(--text); font-size: 0.85em; }}
.filter-btn.active {{ background: var(--accent); color: white; border-color: var(--accent); }}
.compliance-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; margin-bottom: 30px; }}
.compliance-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }}
.compliance-card h3 {{ font-size: 0.95em; margin-bottom: 10px; }}
.progress-bar {{ height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; margin-top: 8px; }}
.progress-fill {{ height: 100%; border-radius: 3px; }}
.remediation {{ max-width: 320px; font-size: 0.86em; color: var(--text-muted); }}
.fw {{ display: inline-block; margin: 0 6px 4px 0; font-size: 0.78em; color: var(--text-muted); white-space: nowrap; }}
.fw b {{ color: var(--text); font-weight: 600; }}
.exec-summary {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 22px 24px; margin-bottom: 20px; }}
.exec-summary p {{ margin-bottom: 10px; color: var(--text); max-width: 80ch; }}
.exec-summary .muted {{ color: var(--text-muted); font-size: 0.92em; }}
.legend {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 8px 20px; font-size: 0.86em; color: var(--text-muted); margin-top: 8px; }}
.callout {{ border-left: 3px solid var(--fail); padding: 8px 12px; margin: 12px 0; background: var(--bg); border-radius: 0 6px 6px 0; font-weight: 600; color: var(--fail); }}
footer {{ color: var(--text-muted); font-size: 0.82em; padding: 24px 0 40px; border-top: 1px solid var(--border); margin-top: 30px; }}
@media (max-width: 720px) {{ .remediation {{ max-width: none; }} th, td {{ padding: 8px; }} }}
@media print {{ .theme-toggle, .filter-bar {{ display: none; }} .section {{ break-inside: avoid; }} .section.collapsed .section-body {{ display: block; }} }}
</style>
</head>
<body>
<header>
<div class="container">
<div>
<div class="eyebrow">Microsoft 365 security assessment</div>
<h1>{tenant}</h1>
<div class="subtitle">{domain} &middot; assessed {timestamp} &middot; {modules} modules &middot; {duration:.0}s</div>
</div>
<button class="theme-toggle" onclick="toggleTheme()">Toggle dark mode</button>
</div>
</header>
<div class="container">
"#,
        tenant = html_escape(&summary.tenant.display_name),
        domain = html_escape(&summary.tenant.primary_domain),
        timestamp = html_escape(&summary.timestamp[..summary.timestamp.len().min(16)].replace('T', " ")),
        modules = summary.modules_run.len(),
        duration = summary.duration_seconds,
    ));

    // Executive summary
    let scored = pass + fail;
    html.push_str(&format!(
        r#"
<div class="exec-summary">
<h2>Summary</h2>
<p><strong>{pass}</strong> of the <strong>{scored}</strong> controls that could be scored {are_in_place} in place ({score:.0}%). {fail} {are_not} not, {warn} {are_partly} partly in place, and {review} {need} a person to review the evidence.</p>
{unknown_line}
{not_licensed_line}
{critical_warning}
<div class="legend">
<span><b>Pass / Fail</b> &mdash; the setting was read and compared with the expected value.</span>
<span><b>Warning</b> &mdash; partly configured, or configured with exceptions worth checking.</span>
<span><b>Review</b> &mdash; evidence collected, but the pass condition depends on your context.</span>
<span><b>Unknown</b> &mdash; the check could not run (permission, licence or API gap). Not scored.</span>
<span><b>Not licensed</b> &mdash; the tenant has no licence for the feature. Not scored.</span>
</div>
</div>
"#,
        pass = pass,
        scored = scored,
        score = summary.score,
        fail = fail,
        warn = warn,
        review = review,
        are_in_place = if pass == 1 { "is" } else { "are" },
        are_not = if fail == 1 { "is" } else { "are" },
        are_partly = if warn == 1 { "is" } else { "are" },
        need = if review == 1 { "needs" } else { "need" },
        unknown_line = if unknown > 0 {
            format!("<p class=\"muted\"><strong>{unknown}</strong> checks could not be evaluated. Each one says why in its Current value; most are missing Graph permissions or APIs this sign-in isn't consented for. They are excluded from the score, so the score may be flattering until they run.</p>")
        } else {
            String::new()
        },
        not_licensed_line = if not_licensed > 0 {
            format!("<p class=\"muted\">{not_licensed} checks need a licence the tenant doesn't have and are excluded from the score.</p>")
        } else {
            String::new()
        },
        critical_warning = if critical > 0 {
            format!("<div class=\"callout\">{critical} critical-severity control{} failing. Start there.</div>", if critical == 1 { " is" } else { "s are" })
        } else {
            String::new()
        },
    ));

    // Stats
    html.push_str(&format!(
        r#"
<div class="stats">
<div class="stat-card score-card"><div class="stat-value">{score:.0}%</div><div class="stat-label">Controls in place</div><div class="stat-hint">pass &divide; (pass + fail)</div></div>
<div class="stat-card"><div class="stat-value" style="color: var(--pass)">{pass}</div><div class="stat-label">Pass</div></div>
<div class="stat-card"><div class="stat-value" style="color: var(--fail)">{fail}</div><div class="stat-label">Fail</div></div>
<div class="stat-card"><div class="stat-value" style="color: var(--warn)">{warn}</div><div class="stat-label">Warning</div></div>
<div class="stat-card"><div class="stat-value" style="color: var(--review)">{review}</div><div class="stat-label">Review</div></div>
<div class="stat-card"><div class="stat-value" style="color: var(--unknown)">{unknown}</div><div class="stat-label">Unknown</div></div>
<div class="stat-card"><div class="stat-value" style="color: var(--text-muted)">{not_licensed}</div><div class="stat-label">Not licensed</div></div>
</div>
"#,
        score = summary.score,
    ));

    // Failing controls by severity
    html.push_str(r#"<div class="severity-bar"><span>Failing by severity:</span>"#);
    for (label, class, n) in [
        ("Critical", "severity-critical", critical),
        ("High", "severity-high", high),
        ("Medium", "severity-medium", medium),
        ("Low", "severity-low", low),
    ] {
        if n > 0 {
            html.push_str(&format!(
                r#"<span class="severity-badge {class}">{label}: {n}</span>"#
            ));
        }
    }
    if critical + high + medium + low == 0 {
        html.push_str("<span>none</span>");
    }
    html.push_str("</div>\n");

    // Filters
    html.push_str(r#"<div class="filter-bar">"#);
    for (label, value) in [
        ("All", "all"),
        ("Fail", "Fail"),
        ("Warning", "Warning"),
        ("Pass", "Pass"),
        ("Review", "Review"),
        ("Unknown", "Unknown"),
        ("Info", "Info"),
        ("Not licensed", "Not Licensed"),
    ] {
        html.push_str(&format!(
            r#"<button class="filter-btn{active}" data-filter="{value}">{label}</button>"#,
            active = if value == "all" { " active" } else { "" }
        ));
    }
    html.push_str("</div>\n");

    // Findings by section
    for (section_name, section_findings) in ordered {
        let s_pass = count(section_findings, FindingStatus::Pass);
        let s_fail = count(section_findings, FindingStatus::Fail);
        let s_warn = count(section_findings, FindingStatus::Warning);
        let s_unknown = count(section_findings, FindingStatus::Unknown);

        html.push_str(&format!(
            r#"
<div class="section">
<div class="section-header" role="button" tabindex="0">
<span>{section}</span>
<div class="section-stats">
<span style="color: var(--pass)">{pass} pass</span>
<span style="color: var(--fail)">{fail} fail</span>
<span style="color: var(--warn)">{warn} warn</span>
{unknown_badge}
</div>
</div>
<div class="section-body">
<table>
<thead>
<tr>
<th>Check</th>
<th>Setting</th>
<th>Status</th>
<th>Severity</th>
<th>Current value</th>
<th>Expected</th>
<th>Remediation</th>
</tr>
</thead>
<tbody>
"#,
            section = html_escape(section_name),
            pass = s_pass,
            fail = s_fail,
            warn = s_warn,
            unknown_badge = if s_unknown > 0 {
                format!("<span style=\"color: var(--unknown)\">{s_unknown} unknown</span>")
            } else {
                String::new()
            },
        ));

        for f in section_findings {
            let refs = framework_refs(f);
            html.push_str(&format!(
                r#"
<tr class="finding-row" data-status="{status}">
<td><code>{check_id}</code></td>
<td>{setting}<br><small style="color: var(--text-muted)">{desc}</small>{refs}</td>
<td><span class="status {status_class}">{status}</span></td>
<td><span class="{sev_class}">{severity}</span></td>
<td><code>{current}</code></td>
<td><code>{expected}</code></td>
<td class="remediation">{remediation}</td>
</tr>
"#,
                check_id = html_escape(&f.check_id),
                setting = html_escape(&f.setting),
                desc = html_escape(&f.description),
                refs = if refs.is_empty() {
                    String::new()
                } else {
                    format!("<div style=\"margin-top:6px\">{refs}</div>")
                },
                status = f.status,
                status_class = f.status.css_class(),
                severity = f.severity,
                sev_class = f.severity.css_class(),
                current = html_escape(&f.current_value),
                expected = html_escape(&f.expected_value),
                remediation = html_escape(&f.remediation),
            ));
        }
        html.push_str("</tbody></table></div></div>\n");
    }

    // Compliance coverage
    if !compliance_results.is_empty() {
        html.push_str(r#"<h2 style="margin: 30px 0 6px">Framework coverage</h2><p class="eyebrow" style="margin-bottom:14px">Indicative: only the controls this scan could map and score</p>"#);
        html.push_str(r#"<div class="compliance-grid">"#);
        // ATT&CK is a threat taxonomy, not a control set; a coverage percentage for it misleads.
        for cr in compliance_results
            .iter()
            .filter(|cr| cr.framework_id != "mitre-attack")
        {
            let bar_color = if cr.pass_rate >= 80.0 {
                "var(--pass)"
            } else if cr.pass_rate >= 50.0 {
                "var(--warn)"
            } else {
                "var(--fail)"
            };
            html.push_str(&format!(
                r#"
<div class="compliance-card">
<h3>{name}</h3>
<div style="display: flex; justify-content: space-between; font-size: 0.86em; color: var(--text-muted);">
<span>{assessed} of {total} controls assessed</span>
<span style="font-weight: 600; color: {color}">{rate:.0}%</span>
</div>
<div class="progress-bar"><div class="progress-fill" style="width: {rate:.0}%; background: {color}"></div></div>
<div style="margin-top: 8px; font-size: 0.82em; color: var(--text-muted)">{passing} passing &middot; {failing} failing</div>
</div>
"#,
                name = html_escape(&cr.framework_name),
                assessed = cr.assessed_controls,
                total = cr.total_controls,
                rate = cr.pass_rate,
                color = bar_color,
                passing = cr.passing_controls,
                failing = cr.failing_controls,
            ));
        }
        html.push_str("</div>\n");
    }

    html.push_str(&format!(
        r#"
<footer>
Generated by {name} {version}. Read-only assessment of tenant configuration at the time shown above; it reflects what the signed-in identity could read, not everything that exists.
The JSON file alongside this report can be imported into <a href="https://jusso-dev.github.io/crownguard/">crownguard</a> to pre-fill a crown-jewel risk assessment.
</footer>
</div>
<script>
function toggleTheme() {{
    const html = document.documentElement;
    const next = html.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', next);
    try {{ localStorage.setItem('m365-theme', next); }} catch (e) {{}}
}}
(function() {{
    try {{ const saved = localStorage.getItem('m365-theme'); if (saved) document.documentElement.setAttribute('data-theme', saved); }} catch (e) {{}}
}})();
document.querySelectorAll('.filter-btn').forEach(btn => btn.addEventListener('click', () => {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const status = btn.dataset.filter;
    document.querySelectorAll('.finding-row').forEach(row => {{
        row.style.display = (status === 'all' || row.dataset.status === status) ? '' : 'none';
    }});
}}));
document.querySelectorAll('.section-header').forEach(header => {{
    const toggle = () => header.parentElement.classList.toggle('collapsed');
    header.addEventListener('click', toggle);
    header.addEventListener('keydown', e => {{ if (e.key === 'Enter' || e.key === ' ') {{ e.preventDefault(); toggle(); }} }});
}});
</script>
</body>
</html>
"#,
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION"),
    ));

    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
