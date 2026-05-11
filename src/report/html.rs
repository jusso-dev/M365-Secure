use anyhow::Result;
use std::collections::HashMap;
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

fn build_html(
    summary: &AssessmentSummary,
    findings: &[Finding],
    compliance_results: &[ComplianceResult],
) -> String {
    let mut html = String::with_capacity(100_000);

    // Count statuses
    let pass_count = findings
        .iter()
        .filter(|f| f.status == FindingStatus::Pass)
        .count();
    let fail_count = findings
        .iter()
        .filter(|f| f.status == FindingStatus::Fail)
        .count();
    let warn_count = findings
        .iter()
        .filter(|f| f.status == FindingStatus::Warning)
        .count();
    let review_count = findings
        .iter()
        .filter(|f| f.status == FindingStatus::Review)
        .count();
    let _info_count = findings
        .iter()
        .filter(|f| f.status == FindingStatus::Info)
        .count();

    // Count by severity
    let critical_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical && f.status == FindingStatus::Fail)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == Severity::High && f.status == FindingStatus::Fail)
        .count();
    let medium_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium && f.status == FindingStatus::Fail)
        .count();
    let low_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Low && f.status == FindingStatus::Fail)
        .count();

    // Group findings by section
    let mut by_section: HashMap<String, Vec<&Finding>> = HashMap::new();
    for f in findings {
        by_section.entry(f.section.clone()).or_default().push(f);
    }

    html.push_str(&format!(r#"<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>M365 Security Assessment - {tenant}</title>
<style>
:root {{
    --bg: #ffffff;
    --bg-card: #f8f9fa;
    --text: #212529;
    --text-muted: #6c757d;
    --border: #dee2e6;
    --pass: #28a745;
    --fail: #dc3545;
    --warn: #ffc107;
    --review: #17a2b8;
    --info: #6c757d;
    --critical: #dc3545;
    --high: #fd7e14;
    --medium: #ffc107;
    --low: #17a2b8;
    --accent: #0078d4;
}}
[data-theme="dark"] {{
    --bg: #1a1a2e;
    --bg-card: #16213e;
    --text: #e8e8e8;
    --text-muted: #a0a0a0;
    --border: #2a2a4a;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
header {{ background: linear-gradient(135deg, #0078d4, #00bcf2); color: white; padding: 40px 0; margin-bottom: 30px; }}
header .container {{ display: flex; justify-content: space-between; align-items: center; }}
h1 {{ font-size: 2em; font-weight: 700; }}
.subtitle {{ opacity: 0.9; margin-top: 5px; }}
.theme-toggle {{ background: rgba(255,255,255,0.2); border: none; color: white; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
.stat-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; text-align: center; }}
.stat-value {{ font-size: 2.5em; font-weight: 700; }}
.stat-label {{ color: var(--text-muted); font-size: 0.9em; margin-top: 4px; }}
.score-card {{ border-left: 4px solid var(--accent); }}
.score-card .stat-value {{ color: var(--accent); }}
.severity-bar {{ display: flex; gap: 10px; margin-bottom: 30px; flex-wrap: wrap; }}
.severity-badge {{ display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }}
.severity-critical {{ background: rgba(220,53,69,0.15); color: var(--critical); }}
.severity-high {{ background: rgba(253,126,20,0.15); color: var(--high); }}
.severity-medium {{ background: rgba(255,193,7,0.15); color: #856404; }}
.severity-low {{ background: rgba(23,162,184,0.15); color: var(--low); }}
.section {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 20px; overflow: hidden; }}
.section-header {{ padding: 16px 24px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; font-weight: 600; font-size: 1.1em; border-bottom: 1px solid var(--border); }}
.section-header:hover {{ background: rgba(0,120,212,0.05); }}
.section-stats {{ display: flex; gap: 12px; font-size: 0.85em; }}
.section-stats span {{ padding: 2px 10px; border-radius: 12px; font-weight: 500; }}
.section-body {{ padding: 0; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
th {{ background: var(--bg); padding: 10px 16px; text-align: left; font-weight: 600; border-bottom: 2px solid var(--border); position: sticky; top: 0; }}
td {{ padding: 10px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }}
tr:hover {{ background: rgba(0,120,212,0.03); }}
.status-pass {{ color: var(--pass); font-weight: 600; }}
.status-fail {{ color: var(--fail); font-weight: 600; }}
.status-warning {{ color: #856404; font-weight: 600; }}
.status-review {{ color: var(--review); font-weight: 600; }}
.status-info {{ color: var(--info); }}
.status-notlicensed {{ color: var(--text-muted); font-style: italic; }}
.filter-bar {{ display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }}
.filter-btn {{ padding: 6px 16px; border: 1px solid var(--border); border-radius: 20px; cursor: pointer; background: var(--bg-card); color: var(--text); font-size: 0.85em; }}
.filter-btn.active {{ background: var(--accent); color: white; border-color: var(--accent); }}
.compliance-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; margin-bottom: 30px; }}
.compliance-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }}
.compliance-card h3 {{ font-size: 1em; margin-bottom: 12px; }}
.progress-bar {{ height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; margin-top: 8px; }}
.progress-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
.remediation {{ max-width: 300px; font-size: 0.85em; color: var(--text-muted); }}
.exec-summary {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 30px; margin-bottom: 30px; }}
.exec-summary h2 {{ margin-bottom: 16px; }}
.exec-summary p {{ margin-bottom: 12px; color: var(--text-muted); }}
@media print {{
    header {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
    .section {{ break-inside: avoid; }}
    .theme-toggle, .filter-bar {{ display: none; }}
}}
</style>
</head>
<body>
<header>
<div class="container">
<div>
<h1>M365 Security Assessment</h1>
<div class="subtitle">{tenant} &mdash; {timestamp}</div>
</div>
<button class="theme-toggle" onclick="toggleTheme()">Toggle Dark Mode</button>
</div>
</header>
<div class="container">
"#,
        tenant = summary.tenant.display_name,
        timestamp = &summary.timestamp[..10],
    ));

    // Executive Summary
    html.push_str(&format!(r#"
<div class="exec-summary">
<h2>Executive Summary</h2>
<p>This assessment evaluated <strong>{total}</strong> security controls across the Microsoft 365 tenant
<strong>{tenant}</strong> ({domain}). The overall security posture score is <strong>{score:.1}%</strong>.</p>
<p>Assessment completed in {duration:.1} seconds covering {modules} modules.</p>
{critical_warning}
</div>
"#,
        total = findings.len(),
        tenant = summary.tenant.display_name,
        domain = summary.tenant.primary_domain,
        score = summary.score,
        duration = summary.duration_seconds,
        modules = summary.modules_run.len(),
        critical_warning = if critical_count > 0 {
            format!("<p style=\"color: var(--critical); font-weight: 600;\">WARNING: {} critical severity findings require immediate attention.</p>", critical_count)
        } else {
            String::new()
        },
    ));

    // Stats Cards
    html.push_str(&format!(
        r#"
<div class="stats">
<div class="stat-card score-card">
<div class="stat-value">{score:.0}%</div>
<div class="stat-label">Security Score</div>
</div>
<div class="stat-card">
<div class="stat-value" style="color: var(--pass)">{pass}</div>
<div class="stat-label">Passing</div>
</div>
<div class="stat-card">
<div class="stat-value" style="color: var(--fail)">{fail}</div>
<div class="stat-label">Failing</div>
</div>
<div class="stat-card">
<div class="stat-value" style="color: var(--warn)">{warn}</div>
<div class="stat-label">Warnings</div>
</div>
<div class="stat-card">
<div class="stat-value" style="color: var(--review)">{review}</div>
<div class="stat-label">Review Required</div>
</div>
</div>
"#,
        score = summary.score,
        pass = pass_count,
        fail = fail_count,
        warn = warn_count,
        review = review_count,
    ));

    // Severity breakdown for failures
    html.push_str(r#"<div class="severity-bar">"#);
    if critical_count > 0 {
        html.push_str(&format!(
            r#"<span class="severity-badge severity-critical">Critical: {}</span>"#,
            critical_count
        ));
    }
    if high_count > 0 {
        html.push_str(&format!(
            r#"<span class="severity-badge severity-high">High: {}</span>"#,
            high_count
        ));
    }
    if medium_count > 0 {
        html.push_str(&format!(
            r#"<span class="severity-badge severity-medium">Medium: {}</span>"#,
            medium_count
        ));
    }
    if low_count > 0 {
        html.push_str(&format!(
            r#"<span class="severity-badge severity-low">Low: {}</span>"#,
            low_count
        ));
    }
    html.push_str("</div>\n");

    // Filter bar
    html.push_str(
        r#"
<div class="filter-bar">
<button class="filter-btn active" onclick="filterFindings('all')">All</button>
<button class="filter-btn" onclick="filterFindings('Fail')">Fail</button>
<button class="filter-btn" onclick="filterFindings('Pass')">Pass</button>
<button class="filter-btn" onclick="filterFindings('Warning')">Warning</button>
<button class="filter-btn" onclick="filterFindings('Review')">Review</button>
<button class="filter-btn" onclick="filterFindings('Info')">Info</button>
</div>
"#,
    );

    // Findings by section
    let section_order = vec![
        "Identity",
        "Conditional Access",
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
        "SharePoint",
        "Teams",
        "Forms",
        "Power BI",
        "Intune",
        "Hybrid",
        "Purview",
        "SOC 2",
        "Inventory",
        "Value Opportunity",
    ];

    for section_name in &section_order {
        if let Some(section_findings) = by_section.get(*section_name) {
            let s_pass = section_findings
                .iter()
                .filter(|f| f.status == FindingStatus::Pass)
                .count();
            let s_fail = section_findings
                .iter()
                .filter(|f| f.status == FindingStatus::Fail)
                .count();
            let s_warn = section_findings
                .iter()
                .filter(|f| f.status == FindingStatus::Warning)
                .count();

            html.push_str(&format!(
                r#"
<div class="section">
<div class="section-header" onclick="this.parentElement.classList.toggle('collapsed')">
<span>{section}</span>
<div class="section-stats">
<span style="background: rgba(40,167,69,0.15); color: var(--pass)">{pass} Pass</span>
<span style="background: rgba(220,53,69,0.15); color: var(--fail)">{fail} Fail</span>
<span style="background: rgba(255,193,7,0.15); color: #856404">{warn} Warn</span>
</div>
</div>
<div class="section-body">
<table>
<thead>
<tr>
<th>Check ID</th>
<th>Setting</th>
<th>Status</th>
<th>Severity</th>
<th>Current Value</th>
<th>Expected</th>
<th>Remediation</th>
</tr>
</thead>
<tbody>
"#,
                section = section_name,
                pass = s_pass,
                fail = s_fail,
                warn = s_warn,
            ));

            for f in section_findings {
                html.push_str(&format!(
                    r#"
<tr class="finding-row" data-status="{status}">
<td><code>{check_id}</code></td>
<td>{setting}<br><small style="color: var(--text-muted)">{desc}</small></td>
<td><span class="{status_class}">{status}</span></td>
<td><span class="{sev_class}">{severity}</span></td>
<td><code>{current}</code></td>
<td><code>{expected}</code></td>
<td class="remediation">{remediation}</td>
</tr>
"#,
                    check_id = html_escape(&f.check_id),
                    setting = html_escape(&f.setting),
                    desc = html_escape(&f.description),
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
    }

    // Handle any sections not in the order list
    for (section_name, section_findings) in &by_section {
        if !section_order.contains(&section_name.as_str()) {
            let s_pass = section_findings
                .iter()
                .filter(|f| f.status == FindingStatus::Pass)
                .count();
            let s_fail = section_findings
                .iter()
                .filter(|f| f.status == FindingStatus::Fail)
                .count();

            html.push_str(&format!(r#"
<div class="section">
<div class="section-header" onclick="this.parentElement.classList.toggle('collapsed')">
<span>{section} ({pass} Pass, {fail} Fail)</span>
</div>
<div class="section-body">
<table>
<thead><tr><th>Check ID</th><th>Setting</th><th>Status</th><th>Severity</th><th>Current</th><th>Expected</th><th>Remediation</th></tr></thead>
<tbody>
"#,
                section = section_name,
                pass = s_pass,
                fail = s_fail,
            ));

            for f in section_findings {
                html.push_str(&format!(
                    r#"<tr class="finding-row" data-status="{status}"><td><code>{id}</code></td><td>{setting}</td><td class="{sc}">{status}</td><td>{sev}</td><td><code>{cur}</code></td><td><code>{exp}</code></td><td class="remediation">{rem}</td></tr>"#,
                    id = html_escape(&f.check_id),
                    setting = html_escape(&f.setting),
                    status = f.status,
                    sc = f.status.css_class(),
                    sev = f.severity,
                    cur = html_escape(&f.current_value),
                    exp = html_escape(&f.expected_value),
                    rem = html_escape(&f.remediation),
                ));
            }
            html.push_str("</tbody></table></div></div>\n");
        }
    }

    // Compliance Results
    if !compliance_results.is_empty() {
        html.push_str(r#"<h2 style="margin: 30px 0 20px">Compliance Framework Coverage</h2>"#);
        html.push_str(r#"<div class="compliance-grid">"#);

        for cr in compliance_results {
            let bar_color = if cr.pass_rate >= 80.0 {
                "var(--pass)"
            } else if cr.pass_rate >= 50.0 {
                "var(--warn)"
            } else {
                "var(--fail)"
            };

            html.push_str(&format!(r#"
<div class="compliance-card">
<h3>{name}</h3>
<div style="display: flex; justify-content: space-between; font-size: 0.9em; color: var(--text-muted);">
<span>{assessed} of {total} controls assessed</span>
<span style="font-weight: 600; color: {color}">{rate:.0}%</span>
</div>
<div class="progress-bar">
<div class="progress-fill" style="width: {rate:.0}%; background: {color}"></div>
</div>
<div style="margin-top: 8px; font-size: 0.85em; color: var(--text-muted)">
{passing} passing &middot; {failing} failing
</div>
</div>
"#,
                name = cr.framework_name,
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

    // JavaScript
    html.push_str(
        r#"
</div>
<script>
function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const next = current === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', next);
    localStorage.setItem('m365-theme', next);
}
(function() {
    const saved = localStorage.getItem('m365-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
})();

function filterFindings(status) {
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.finding-row').forEach(row => {
        if (status === 'all' || row.dataset.status === status) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

document.querySelectorAll('.section-header').forEach(header => {
    header.addEventListener('click', () => {
        const body = header.nextElementSibling;
        body.style.display = body.style.display === 'none' ? '' : 'none';
    });
});
</script>
</body>
</html>
"#,
    );

    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
