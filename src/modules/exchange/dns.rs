//! Email authentication DNS checks: SPF, DKIM and DMARC per sending domain.
//!
//! Parsing is pure and unit-tested; resolution goes through `trust_dns_resolver`. DKIM combines the
//! public selector CNAMEs with `Get-DkimSigningConfig` so a Pass means Exchange Online really signs.

use serde_json::Value;
use std::collections::HashSet;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

use super::exo::{bool_or, finding, str_of};
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;

const CATEGORY: &str = "Exchange Online";
const SECTION: &str = "Email Authentication";

/// `*.onmicrosoft.com` and `*.mail.onmicrosoft.com` are Microsoft-managed and never customer sending domains.
pub fn is_customer_domain(domain: &str) -> bool {
    !domain.to_ascii_lowercase().ends_with(".onmicrosoft.com")
}

// ─── SPF ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllQualifier {
    /// `-all`
    HardFail,
    /// `~all`
    SoftFail,
    /// `?all`
    Neutral,
    /// `+all` or bare `all`
    Pass,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfRecord {
    pub all: AllQualifier,
    /// Terms in this record that cost a DNS lookup (include, a, mx, ptr, exists, redirect).
    pub lookup_terms: usize,
    pub includes: Vec<String>,
    pub redirect: Option<String>,
}

pub fn parse_spf(txt: &str) -> SpfRecord {
    let mut rec = SpfRecord {
        all: AllQualifier::Missing,
        lookup_terms: 0,
        includes: Vec::new(),
        redirect: None,
    };
    for term in txt.split_whitespace().skip(1) {
        let lower = term.to_ascii_lowercase();
        let (qualifier, body) = match lower.chars().next() {
            Some(q @ ('+' | '-' | '~' | '?')) => (q, &lower[1..]),
            _ => ('+', lower.as_str()),
        };
        if body == "all" {
            rec.all = match qualifier {
                '-' => AllQualifier::HardFail,
                '~' => AllQualifier::SoftFail,
                '?' => AllQualifier::Neutral,
                _ => AllQualifier::Pass,
            };
            continue;
        }
        if let Some(target) = body.strip_prefix("include:") {
            rec.lookup_terms += 1;
            rec.includes.push(target.to_string());
        } else if let Some(target) = body.strip_prefix("redirect=") {
            rec.lookup_terms += 1;
            rec.redirect = Some(target.to_string());
        } else if body == "a"
            || body == "mx"
            || body == "ptr"
            || body.starts_with("a:")
            || body.starts_with("a/")
            || body.starts_with("mx:")
            || body.starts_with("mx/")
            || body.starts_with("ptr:")
            || body.starts_with("exists:")
        {
            rec.lookup_terms += 1;
        }
    }
    rec
}

/// Status for a domain's SPF given its record(s) and the total lookup count (this record plus the
/// records it includes or redirects to).
pub fn evaluate_spf(records: &[String], total_lookups: usize) -> (FindingStatus, String) {
    match records {
        [] => (FindingStatus::Fail, "No SPF record (v=spf1) published".to_string()),
        [_, _, ..] => (
            FindingStatus::Fail,
            format!(
                "{} SPF records published; RFC 7208 requires exactly one, receivers treat this as a permanent error",
                records.len()
            ),
        ),
        [record] => {
            let spf = parse_spf(record);
            let lookups_note = if total_lookups > 10 {
                format!("; {} DNS lookups exceed the limit of 10, so receivers return PermError", total_lookups)
            } else {
                format!("; {} of 10 DNS lookups used", total_lookups)
            };
            match spf.all {
                AllQualifier::HardFail if total_lookups > 10 => (
                    FindingStatus::Warning,
                    format!("SPF ends in -all but is over the lookup limit{}: {}", lookups_note, record),
                ),
                AllQualifier::HardFail => (FindingStatus::Pass, format!("SPF ends in -all{}: {}", lookups_note, record)),
                AllQualifier::SoftFail => (
                    FindingStatus::Warning,
                    format!("SPF ends in ~all (soft fail); move to -all once senders are complete{}: {}", lookups_note, record),
                ),
                AllQualifier::Neutral => (
                    FindingStatus::Fail,
                    format!("SPF ends in ?all (neutral), which gives receivers no signal{}: {}", lookups_note, record),
                ),
                AllQualifier::Pass => (
                    FindingStatus::Fail,
                    format!("SPF ends in +all, which authorises every sender{}: {}", lookups_note, record),
                ),
                AllQualifier::Missing => (
                    FindingStatus::Fail,
                    format!("SPF has no all mechanism, so unlisted senders are not failed{}: {}", lookups_note, record),
                ),
            }
        }
    }
}

// ─── DMARC ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    pub p: Option<String>,
    pub sp: Option<String>,
    pub pct: u32,
    pub rua: Vec<String>,
}

pub fn parse_dmarc(txt: &str) -> DmarcRecord {
    let mut rec = DmarcRecord {
        p: None,
        sp: None,
        pct: 100,
        rua: Vec::new(),
    };
    for tag in txt.split(';') {
        let Some((k, v)) = tag.split_once('=') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "p" => rec.p = Some(v.to_ascii_lowercase()),
            "sp" => rec.sp = Some(v.to_ascii_lowercase()),
            "pct" => rec.pct = v.parse().unwrap_or(100),
            "rua" => {
                rec.rua = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            _ => {}
        }
    }
    rec
}

fn is_enforcing(policy: &str) -> bool {
    policy == "reject" || policy == "quarantine"
}

pub fn evaluate_dmarc(records: &[String]) -> (FindingStatus, String) {
    match records {
        [] => (
            FindingStatus::Fail,
            "No DMARC record published at _dmarc".to_string(),
        ),
        [_, _, ..] => (
            FindingStatus::Fail,
            format!(
                "{} DMARC records published; receivers ignore DMARC when more than one exists",
                records.len()
            ),
        ),
        [record] => {
            let d = parse_dmarc(record);
            let rua_note = if d.rua.is_empty() {
                "; no rua= address, so aggregate reports are not collected"
            } else {
                "; aggregate reports go to rua="
            };
            let Some(p) = d.p.as_deref() else {
                return (
                    FindingStatus::Fail,
                    format!("DMARC record has no p= tag and is invalid: {}", record),
                );
            };
            if !is_enforcing(p) {
                let msg = if p == "none" {
                    format!(
                        "DMARC p=none only monitors; spoofed mail is still delivered{}: {}",
                        rua_note, record
                    )
                } else {
                    format!("DMARC p={} is not a valid policy: {}", p, record)
                };
                return (FindingStatus::Fail, msg);
            }
            if d.pct < 100 {
                return (
                    FindingStatus::Warning,
                    format!(
                        "DMARC p={} applies to only pct={} of mail{}: {}",
                        p, d.pct, rua_note, record
                    ),
                );
            }
            if let Some(sp) = d.sp.as_deref() {
                if !is_enforcing(sp) {
                    return (
                        FindingStatus::Warning,
                        format!(
                            "DMARC p={} but sp={} leaves subdomains unprotected{}: {}",
                            p, sp, rua_note, record
                        ),
                    );
                }
            }
            (
                FindingStatus::Pass,
                format!("DMARC p={}{}: {}", p, rua_note, record),
            )
        }
    }
}

// ─── Resolution ─────────────────────────────────────────────────────────────

async fn txt_records(resolver: &TokioAsyncResolver, name: &str) -> Vec<String> {
    match resolver.txt_lookup(name).await {
        Ok(lookup) => lookup
            .iter()
            .map(|r| {
                r.iter()
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect::<String>()
            })
            .collect(),
        Err(_) => vec![],
    }
}

async fn spf_records(resolver: &TokioAsyncResolver, name: &str) -> Vec<String> {
    txt_records(resolver, name)
        .await
        .into_iter()
        .filter(|t| t.to_ascii_lowercase().starts_with("v=spf1"))
        .collect()
}

async fn has_mx(resolver: &TokioAsyncResolver, domain: &str) -> bool {
    resolver
        .mx_lookup(domain)
        .await
        .map(|mx| mx.iter().next().is_some())
        .unwrap_or(false)
}

/// A domain is assessed when it can receive or send mail: it has an MX record or publishes SPF.
pub async fn is_sending_domain(resolver: &TokioAsyncResolver, domain: &str) -> bool {
    if !is_customer_domain(domain) {
        return false;
    }
    has_mx(resolver, domain).await || !spf_records(resolver, domain).await.is_empty()
}

/// Count DNS lookups the record tree costs, following include/redirect up to RFC limits.
async fn total_spf_lookups(resolver: &TokioAsyncResolver, domain: &str, record: &str) -> usize {
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(domain.to_ascii_lowercase());
    let mut total = 0usize;
    let mut queue: Vec<String> = Vec::new();
    let spf = parse_spf(record);
    total += spf.lookup_terms;
    queue.extend(spf.includes);
    queue.extend(spf.redirect);
    while let Some(next) = queue.pop() {
        if total > 20 || !seen.insert(next.clone()) {
            continue;
        }
        if let [rec] = spf_records(resolver, &next).await.as_slice() {
            let inner = parse_spf(rec);
            total += inner.lookup_terms;
            queue.extend(inner.includes);
            queue.extend(inner.redirect);
        }
    }
    total
}

async fn cname_resolves(resolver: &TokioAsyncResolver, name: &str) -> bool {
    resolver
        .lookup(name, RecordType::CNAME)
        .await
        .map(|l| l.iter().next().is_some())
        .unwrap_or(false)
}

/// Row from `Get-DkimSigningConfig` for `domain`, if the cmdlet returned.
fn dkim_config_for<'a>(configs: &'a [Value], domain: &str) -> Option<&'a Value> {
    configs.iter().find(|c| {
        str_of(c, "Domain")
            .or_else(|| str_of(c, "Identity"))
            .is_some_and(|d| d.eq_ignore_ascii_case(domain))
    })
}

/// SPF, DKIM and DMARC findings for one domain. `dkim_configs` is the `Get-DkimSigningConfig`
/// result or the error that stopped it.
pub async fn check_domain(
    resolver: &TokioAsyncResolver,
    domain: &str,
    dkim_configs: &Result<Vec<Value>, String>,
    registry: &ControlRegistry,
) -> Vec<Finding> {
    let mut out = Vec::with_capacity(3);

    // SPF
    let spf = spf_records(resolver, domain).await;
    let lookups = match spf.as_slice() {
        [rec] => total_spf_lookups(resolver, domain, rec).await,
        _ => 0,
    };
    let (status, current) = evaluate_spf(&spf, lookups);
    out.push(
        finding(
            registry,
            "DNS-SPF-001",
            CATEGORY,
            SECTION,
            "SPF Record",
            &format!("SPF record for {} ends in -all and stays within 10 DNS lookups", domain),
        )
        .status(status)
        .current_value(current)
        .expected_value("One v=spf1 record ending in -all, at most 10 DNS lookups")
        .remediation(format!(
            "Publish one TXT record on {} listing every legitimate sender and ending in -all, for example \
             \"v=spf1 include:spf.protection.outlook.com -all\". Flatten or remove includes if lookups exceed 10.",
            domain
        ))
        .affected_resources(vec![domain.to_string()])
        .build(),
    );

    // DKIM
    let sel1 = cname_resolves(resolver, &format!("selector1._domainkey.{}", domain)).await;
    let sel2 = cname_resolves(resolver, &format!("selector2._domainkey.{}", domain)).await;
    let (status, current) = match dkim_configs {
        _ if !(sel1 && sel2) => (
            FindingStatus::Fail,
            format!(
                "selector1 CNAME {}, selector2 CNAME {}; Exchange Online cannot sign without both",
                if sel1 { "present" } else { "missing" },
                if sel2 { "present" } else { "missing" }
            ),
        ),
        Ok(configs) => match dkim_config_for(configs, domain) {
            Some(cfg) if bool_or(cfg, "Enabled", false) => (
                FindingStatus::Pass,
                "DKIM signing enabled in Exchange Online and both selector CNAMEs resolve".to_string(),
            ),
            Some(_) => (
                FindingStatus::Fail,
                "Selector CNAMEs resolve but DKIM signing is disabled in Exchange Online (Get-DkimSigningConfig Enabled = False)"
                    .to_string(),
            ),
            None => (
                FindingStatus::Fail,
                "Selector CNAMEs resolve but no DKIM signing configuration exists for this domain in Exchange Online".to_string(),
            ),
        },
        Err(e) => (
            FindingStatus::Unknown,
            format!("Both selector CNAMEs resolve but the signing state could not be read: {}", e),
        ),
    };
    out.push(
        finding(
            registry,
            "DNS-DKIM-001",
            CATEGORY,
            SECTION,
            "DKIM Signing",
            &format!("DKIM signing is enabled for {} and its selector CNAMEs resolve", domain),
        )
        .status(status)
        .current_value(current)
        .expected_value("Get-DkimSigningConfig Enabled = True and selector1/selector2 CNAMEs published")
        .remediation(format!(
            "In the Defender portal go to Email & collaboration > Policies & rules > Threat policies > Email authentication \
             settings > DKIM, select {}, publish the two CNAME records it shows, then enable signing \
             (or run Set-DkimSigningConfig -Identity {} -Enabled $true).",
            domain, domain
        ))
        .affected_resources(vec![domain.to_string()])
        .build(),
    );

    // DMARC
    let dmarc: Vec<String> = txt_records(resolver, &format!("_dmarc.{}", domain))
        .await
        .into_iter()
        .filter(|t| t.to_ascii_lowercase().starts_with("v=dmarc1"))
        .collect();
    let (status, current) = evaluate_dmarc(&dmarc);
    out.push(
        finding(
            registry,
            "DNS-DMARC-001",
            CATEGORY,
            SECTION,
            "DMARC Policy",
            &format!("DMARC for {} enforces p=quarantine or p=reject on all mail", domain),
        )
        .status(status)
        .current_value(current)
        .expected_value("v=DMARC1 with p=reject or p=quarantine, pct=100, sp not weaker than p, rua= set")
        .remediation(format!(
            "Publish a TXT record at _dmarc.{} such as \"v=DMARC1; p=reject; rua=mailto:dmarc@{}\". Start at p=none \
             with reporting only if senders are still being inventoried, then move to quarantine and reject.",
            domain, domain
        ))
        .affected_resources(vec![domain.to_string()])
        .build(),
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_parsing_counts_lookup_terms_and_all() {
        let spf = parse_spf("v=spf1 include:spf.protection.outlook.com ip4:1.2.3.4 a mx:mail.example.com exists:%{i}.x -all");
        assert_eq!(spf.all, AllQualifier::HardFail);
        assert_eq!(spf.lookup_terms, 4);
        assert_eq!(spf.includes, vec!["spf.protection.outlook.com"]);

        let spf = parse_spf("v=spf1 redirect=_spf.example.com");
        assert_eq!(spf.all, AllQualifier::Missing);
        assert_eq!(spf.redirect.as_deref(), Some("_spf.example.com"));
        assert_eq!(spf.lookup_terms, 1);

        assert_eq!(parse_spf("v=spf1 ~all").all, AllQualifier::SoftFail);
        assert_eq!(parse_spf("v=spf1 ?all").all, AllQualifier::Neutral);
        assert_eq!(parse_spf("v=spf1 +all").all, AllQualifier::Pass);
        assert_eq!(parse_spf("v=spf1 all").all, AllQualifier::Pass);
    }

    #[test]
    fn spf_evaluation() {
        let hard = vec!["v=spf1 include:spf.protection.outlook.com -all".to_string()];
        assert_eq!(evaluate_spf(&hard, 1).0, FindingStatus::Pass);
        assert_eq!(evaluate_spf(&hard, 11).0, FindingStatus::Warning);
        let soft = vec!["v=spf1 include:spf.protection.outlook.com ~all".to_string()];
        assert_eq!(evaluate_spf(&soft, 1).0, FindingStatus::Warning);
        let plus = vec!["v=spf1 +all".to_string()];
        assert_eq!(evaluate_spf(&plus, 0).0, FindingStatus::Fail);
        assert_eq!(evaluate_spf(&[], 0).0, FindingStatus::Fail);
        let two = vec!["v=spf1 -all".to_string(), "v=spf1 ~all".to_string()];
        assert_eq!(evaluate_spf(&two, 0).0, FindingStatus::Fail);
    }

    #[test]
    fn dmarc_parsing_reads_tags_not_substrings() {
        // `sp=reject` must not be mistaken for `p=reject`.
        let d =
            parse_dmarc("v=DMARC1; sp=reject; p=none; pct=50; rua=mailto:a@x.com, mailto:b@x.com");
        assert_eq!(d.p.as_deref(), Some("none"));
        assert_eq!(d.sp.as_deref(), Some("reject"));
        assert_eq!(d.pct, 50);
        assert_eq!(d.rua.len(), 2);

        let d = parse_dmarc("v=DMARC1;p=REJECT");
        assert_eq!(d.p.as_deref(), Some("reject"));
        assert_eq!(d.pct, 100);
        assert!(d.rua.is_empty());
    }

    #[test]
    fn dmarc_evaluation() {
        let s = |r: &str| evaluate_dmarc(&[r.to_string()]).0;
        assert_eq!(
            s("v=DMARC1; p=reject; rua=mailto:d@x.com"),
            FindingStatus::Pass
        );
        assert_eq!(s("v=DMARC1; p=quarantine"), FindingStatus::Pass);
        assert_eq!(s("v=DMARC1; p=reject; pct=20"), FindingStatus::Warning);
        assert_eq!(s("v=DMARC1; p=reject; sp=none"), FindingStatus::Warning);
        assert_eq!(s("v=DMARC1; sp=reject; p=none"), FindingStatus::Fail);
        assert_eq!(s("v=DMARC1; p=none"), FindingStatus::Fail);
        assert_eq!(s("v=DMARC1; rua=mailto:d@x.com"), FindingStatus::Fail);
        assert_eq!(evaluate_dmarc(&[]).0, FindingStatus::Fail);
        assert_eq!(
            evaluate_dmarc(&[
                "v=DMARC1; p=reject".to_string(),
                "v=DMARC1; p=none".to_string()
            ])
            .0,
            FindingStatus::Fail
        );
    }

    #[test]
    fn microsoft_domains_are_skipped() {
        assert!(!is_customer_domain("contoso.onmicrosoft.com"));
        assert!(!is_customer_domain("contoso.mail.onmicrosoft.com"));
        assert!(is_customer_domain("contoso.com"));
    }
}
