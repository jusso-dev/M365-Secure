//! Exchange Online Protection and Defender for Office 365 policy checks, read from the policy
//! cmdlets rather than Secure Score. Evaluation functions are pure so fixture JSON can be tested.

use serde_json::{json, Value};

use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::modules::exchange::exo::{
    bool_or, finding, has_mdo, has_mdo_p2, i64_of, list_preview, name_of, need, rule_enabled,
    str_of, strs_of, Exo, Fetched,
};
use crate::modules::record_one;

const CATEGORY: &str = "Security";
const SECTION_EOP: &str = "Exchange Online Protection";
const SECTION_MDO: &str = "Defender for Office 365";

const STANDARD: &str = "Standard Preset Security Policy";
const STRICT: &str = "Strict Preset Security Policy";
const BUILT_IN: &str = "Built-In Protection Policy";

fn is_default(p: &Value) -> bool {
    bool_or(p, "IsDefault", false) || name_of(p).eq_ignore_ascii_case("Default")
}

fn preset_name(name: &str) -> bool {
    name.starts_with(STANDARD) || name.starts_with(STRICT) || name.starts_with(BUILT_IN)
}

fn not_licensed(
    registry: &ControlRegistry,
    id: &str,
    section: &str,
    setting: &str,
    description: &str,
    plan: &str,
) -> Finding {
    finding(registry, id, CATEGORY, section, setting, description)
        .status(FindingStatus::NotLicensed)
        .current_value(format!("{} not detected in tenant service plans", plan))
        .expected_value(format!("{} licensed and the policy configured", plan))
        .remediation(format!(
            "This control needs {}; license it or record the compensating control in crownguard.",
            plan
        ))
        .build()
}

// ─── Anti-phishing ──────────────────────────────────────────────────────────

/// Settings an anti-phishing policy is missing against the recommended configuration.
pub fn antiphish_gaps(p: &Value, mdo: bool) -> Vec<String> {
    let mut gaps = Vec::new();
    let want_true = |key: &str, gaps: &mut Vec<String>| {
        if !bool_or(p, key, false) {
            gaps.push(format!("{} = False", key));
        }
    };
    want_true("EnableSpoofIntelligence", &mut gaps);
    want_true("HonorDmarcPolicy", &mut gaps);
    if !mdo {
        return gaps;
    }
    if i64_of(p, "PhishThresholdLevel").unwrap_or(1) < 2 {
        gaps.push("PhishThresholdLevel < 2 (Aggressive)".to_string());
    }
    for key in [
        "EnableMailboxIntelligence",
        "EnableMailboxIntelligenceProtection",
        "EnableTargetedUserProtection",
        "EnableOrganizationDomainsProtection",
        "EnableFirstContactSafetyTips",
        "EnableSimilarUsersSafetyTips",
        "EnableSimilarDomainsSafetyTips",
        "EnableUnusualCharactersSafetyTips",
    ] {
        want_true(key, &mut gaps);
    }
    for key in [
        "TargetedUserProtectionAction",
        "TargetedDomainProtectionAction",
        "MailboxIntelligenceProtectionAction",
    ] {
        if !str_of(p, key).is_some_and(|a| a.eq_ignore_ascii_case("Quarantine")) {
            gaps.push(format!("{} != Quarantine", key));
        }
    }
    gaps
}

pub fn evaluate_antiphish(policies: &[Value], mdo: bool) -> (FindingStatus, String) {
    let enabled: Vec<&Value> = policies
        .iter()
        .filter(|p| bool_or(p, "Enabled", true))
        .collect();
    if enabled.is_empty() {
        return (
            FindingStatus::Fail,
            "No enabled anti-phishing policy".to_string(),
        );
    }
    let mut best: Option<(&Value, Vec<String>)> = None;
    for p in &enabled {
        let gaps = antiphish_gaps(p, mdo);
        if best.as_ref().is_none_or(|(_, g)| gaps.len() < g.len()) {
            best = Some((p, gaps));
        }
    }
    let (policy, gaps) = best.expect("at least one enabled policy");
    let name = name_of(policy);
    let scope_note = if is_default(policy) {
        "default policy, applies to everyone"
    } else if preset_name(&name) {
        "preset policy, applies to the recipients in its preset rule"
    } else {
        "custom policy, applies only to the recipients in its rule"
    };
    let mdo_note = if mdo {
        ""
    } else {
        " (impersonation protection needs Defender for Office 365)"
    };
    if gaps.is_empty() {
        (
            FindingStatus::Pass,
            format!(
                "'{}' meets the recommended anti-phishing settings ({}){}",
                name, scope_note, mdo_note
            ),
        )
    } else if gaps.len() <= 3 {
        (
            FindingStatus::Warning,
            format!(
                "Best policy '{}' ({}) is missing: {}{}",
                name,
                scope_note,
                gaps.join("; "),
                mdo_note
            ),
        )
    } else {
        (
            FindingStatus::Fail,
            format!(
                "Best policy '{}' ({}) is missing {} settings: {}{}",
                name,
                scope_note,
                gaps.len(),
                gaps.join("; "),
                mdo_note
            ),
        )
    }
}

// ─── Outbound spam ──────────────────────────────────────────────────────────

pub fn evaluate_outbound_notifications(policies: &[Value]) -> (FindingStatus, String) {
    let Some(p) = policies.iter().find(|p| is_default(p)) else {
        return (
            FindingStatus::Fail,
            "No default outbound spam policy returned".to_string(),
        );
    };
    let bcc = bool_or(p, "BccSuspiciousOutboundMail", false);
    let bcc_to = strs_of(p, "BccSuspiciousOutboundAdditionalRecipients");
    let notify = bool_or(p, "NotifyOutboundSpam", false);
    let notify_to = strs_of(p, "NotifyOutboundSpamRecipients");
    let ok = bcc && !bcc_to.is_empty() && notify && !notify_to.is_empty();
    (
        if ok { FindingStatus::Pass } else { FindingStatus::Fail },
        format!(
            "BccSuspiciousOutboundMail={} ({} recipient(s)), NotifyOutboundSpam={} ({} recipient(s))",
            bcc,
            bcc_to.len(),
            notify,
            notify_to.len()
        ),
    )
}

pub fn evaluate_outbound_limits(policies: &[Value]) -> (FindingStatus, String) {
    let Some(p) = policies.iter().find(|p| is_default(p)) else {
        return (
            FindingStatus::Fail,
            "No default outbound spam policy returned".to_string(),
        );
    };
    let ext = i64_of(p, "RecipientLimitExternalPerHour").unwrap_or(0);
    let int = i64_of(p, "RecipientLimitInternalPerHour").unwrap_or(0);
    let day = i64_of(p, "RecipientLimitPerDay").unwrap_or(0);
    let action = str_of(p, "ActionWhenThresholdReached").unwrap_or("");
    let mut gaps = Vec::new();
    if !(1..=500).contains(&ext) {
        gaps.push(format!(
            "RecipientLimitExternalPerHour={} (want 1-500; 0 means service default)",
            ext
        ));
    }
    if !(1..=1000).contains(&int) {
        gaps.push(format!(
            "RecipientLimitInternalPerHour={} (want 1-1000)",
            int
        ));
    }
    if !(1..=1000).contains(&day) {
        gaps.push(format!("RecipientLimitPerDay={} (want 1-1000)", day));
    }
    if !action.eq_ignore_ascii_case("BlockUser") {
        gaps.push(format!(
            "ActionWhenThresholdReached={} (want BlockUser)",
            action
        ));
    }
    if gaps.is_empty() {
        (
            FindingStatus::Pass,
            format!(
                "External/hour {}, internal/hour {}, per day {}, action BlockUser",
                ext, int, day
            ),
        )
    } else {
        (FindingStatus::Fail, gaps.join("; "))
    }
}

// ─── Anti-malware ───────────────────────────────────────────────────────────

/// High-risk attachment types from the CIS comprehensive list. Pass needs all of them blocked.
pub const CORE_BLOCKED_TYPES: &[&str] = &[
    "ace",
    "ani",
    "app",
    "appref-ms",
    "bat",
    "chm",
    "cmd",
    "com",
    "cpl",
    "diagcab",
    "dll",
    "docm",
    "exe",
    "hta",
    "img",
    "inf",
    "ins",
    "iso",
    "jar",
    "jnlp",
    "js",
    "jse",
    "library-ms",
    "lnk",
    "mde",
    "msc",
    "msi",
    "msp",
    "mst",
    "pif",
    "ps1",
    "psm1",
    "py",
    "reg",
    "scf",
    "scr",
    "sct",
    "search-ms",
    "settingcontent-ms",
    "shb",
    "sys",
    "url",
    "vb",
    "vbe",
    "vbs",
    "vhd",
    "vhdx",
    "vxd",
    "wsc",
    "wsf",
    "wsh",
    "xll",
];

pub fn evaluate_file_filter(policies: &[Value]) -> (FindingStatus, String, Vec<String>) {
    let off: Vec<String> = policies
        .iter()
        .filter(|p| !bool_or(p, "EnableFileFilter", false))
        .map(name_of)
        .collect();
    if off.is_empty() {
        (
            FindingStatus::Pass,
            format!(
                "EnableFileFilter = True on all {} anti-malware policy(ies)",
                policies.len()
            ),
            vec![],
        )
    } else {
        (
            FindingStatus::Fail,
            format!(
                "Common attachments filter off on: {}",
                list_preview(&off, 10)
            ),
            off,
        )
    }
}

pub fn evaluate_internal_malware_notifications(policies: &[Value]) -> (FindingStatus, String) {
    let Some(p) = policies.iter().find(|p| is_default(p)) else {
        return (
            FindingStatus::Fail,
            "No default anti-malware policy returned".to_string(),
        );
    };
    let notify = bool_or(p, "EnableInternalSenderAdminNotifications", false);
    let addr = str_of(p, "InternalSenderAdminAddress").unwrap_or("");
    let ok = notify && !addr.is_empty();
    (
        if ok {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        },
        format!(
            "EnableInternalSenderAdminNotifications={} InternalSenderAdminAddress={}",
            notify,
            if addr.is_empty() { "(none)" } else { addr }
        ),
    )
}

pub fn evaluate_blocked_types(policies: &[Value]) -> (FindingStatus, String) {
    let Some(p) = policies.iter().find(|p| is_default(p)).or(policies.first()) else {
        return (
            FindingStatus::Fail,
            "No anti-malware policy returned".to_string(),
        );
    };
    if !bool_or(p, "EnableFileFilter", false) {
        return (
            FindingStatus::Fail,
            format!("'{}' has the common attachments filter off", name_of(p)),
        );
    }
    let types: Vec<String> = strs_of(p, "FileTypes")
        .into_iter()
        .map(|t| t.trim_start_matches('.').to_ascii_lowercase())
        .collect();
    let missing: Vec<&str> = CORE_BLOCKED_TYPES
        .iter()
        .copied()
        .filter(|t| !types.iter().any(|x| x == t))
        .collect();
    let covered = CORE_BLOCKED_TYPES.len() - missing.len();
    let msg = format!(
        "'{}' blocks {} type(s), covering {} of {} high-risk types{}",
        name_of(p),
        types.len(),
        covered,
        CORE_BLOCKED_TYPES.len(),
        if missing.is_empty() {
            String::new()
        } else {
            format!("; missing: {}", missing.join(", "))
        }
    );
    let status = if missing.is_empty() {
        FindingStatus::Pass
    } else if covered * 10 >= CORE_BLOCKED_TYPES.len() * 8 {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    };
    (status, msg)
}

// ─── Safe Links / Safe Attachments ──────────────────────────────────────────

/// Names of policies that are applied: a custom rule in `Enabled` state, or a preset whose
/// preset rule is enabled. `policy_key` is the rule property naming the policy.
fn applied_policy_names(
    rules: &[Value],
    policy_key: &str,
    enabled_presets: &[String],
) -> Vec<String> {
    let mut names: Vec<String> = rules
        .iter()
        .filter(|r| rule_enabled(r))
        .filter_map(|r| str_of(r, policy_key).map(String::from))
        .collect();
    names.extend(enabled_presets.iter().cloned());
    names.push(BUILT_IN.to_string());
    names
}

fn is_applied(policy: &Value, applied: &[String]) -> bool {
    let name = name_of(policy);
    applied
        .iter()
        .any(|a| name.eq_ignore_ascii_case(a) || (preset_name(a) && name.starts_with(a.as_str())))
}

pub fn safelinks_gaps(p: &Value) -> Vec<String> {
    let mut gaps = Vec::new();
    for key in [
        "EnableSafeLinksForEmail",
        "EnableSafeLinksForTeams",
        "EnableSafeLinksForOffice",
        "TrackClicks",
        "ScanUrls",
        "EnableForInternalSenders",
        "DeliverMessageAfterScan",
    ] {
        if !bool_or(p, key, false) {
            gaps.push(format!("{} = False", key));
        }
    }
    if bool_or(p, "AllowClickThrough", true) {
        gaps.push("AllowClickThrough = True".to_string());
    }
    if bool_or(p, "DisableUrlRewrite", false) {
        gaps.push("DisableUrlRewrite = True".to_string());
    }
    gaps
}

pub fn evaluate_safelinks(
    policies: &[Value],
    rules: &[Value],
    enabled_presets: &[String],
) -> (FindingStatus, String) {
    let applied = applied_policy_names(rules, "SafeLinksPolicy", enabled_presets);
    let candidates: Vec<&Value> = policies
        .iter()
        .filter(|p| is_applied(p, &applied))
        .collect();
    if candidates.is_empty() {
        return (
            FindingStatus::Fail,
            format!(
                "{} Safe Links policy(ies) exist but none is applied by an enabled rule",
                policies.len()
            ),
        );
    }
    let (best, gaps) = candidates
        .iter()
        .map(|p| (*p, safelinks_gaps(p)))
        .min_by_key(|(_, g)| g.len())
        .expect("non-empty");
    let name = name_of(best);
    if gaps.is_empty() {
        (
            FindingStatus::Pass,
            format!(
                "Applied policy '{}' meets the recommended Safe Links settings",
                name
            ),
        )
    } else if gaps.len() <= 2 {
        (
            FindingStatus::Warning,
            format!("Applied policy '{}' is missing: {}", name, gaps.join("; ")),
        )
    } else {
        (
            FindingStatus::Fail,
            format!("Applied policy '{}' is missing: {}", name, gaps.join("; ")),
        )
    }
}

pub fn evaluate_safeattachments(
    policies: &[Value],
    rules: &[Value],
    enabled_presets: &[String],
) -> (FindingStatus, String) {
    let applied = applied_policy_names(rules, "SafeAttachmentPolicy", enabled_presets);
    let good: Vec<String> = policies
        .iter()
        .filter(|p| is_applied(p, &applied))
        .filter(|p| bool_or(p, "Enable", false))
        .filter(|p| {
            str_of(p, "Action").is_some_and(|a| {
                a.eq_ignore_ascii_case("Block") || a.eq_ignore_ascii_case("DynamicDelivery")
            })
        })
        .map(|p| format!("{} ({})", name_of(p), str_of(p, "Action").unwrap_or("")))
        .collect();
    if good.is_empty() {
        (
            FindingStatus::Fail,
            format!(
                "{} Safe Attachments policy(ies); none that is applied has Enable = True with Action Block or DynamicDelivery",
                policies.len()
            ),
        )
    } else {
        (
            FindingStatus::Pass,
            format!("Applied and enabled: {}", good.join(", ")),
        )
    }
}

pub fn evaluate_atp_global(policy: &Value, p2: bool) -> (FindingStatus, String) {
    let spo = bool_or(policy, "EnableATPForSPOTeamsODB", false);
    let docs = bool_or(policy, "EnableSafeDocs", false);
    let open = bool_or(policy, "AllowSafeDocsOpen", true);
    let mut gaps = Vec::new();
    if !spo {
        gaps.push("EnableATPForSPOTeamsODB = False");
    }
    if p2 {
        if !docs {
            gaps.push("EnableSafeDocs = False");
        }
        if open {
            gaps.push("AllowSafeDocsOpen = True");
        }
    }
    let current = format!(
        "EnableATPForSPOTeamsODB={} EnableSafeDocs={} AllowSafeDocsOpen={}{}",
        spo,
        docs,
        open,
        if p2 {
            ""
        } else {
            " (Safe Documents needs Defender for Office 365 Plan 2, not evaluated)"
        }
    );
    if gaps.is_empty() {
        (FindingStatus::Pass, current)
    } else {
        (
            FindingStatus::Fail,
            format!("{}; missing: {}", current, gaps.join(", ")),
        )
    }
}

// ─── Preset security policies ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetRule {
    pub enabled: bool,
    pub users: usize,
    pub groups: usize,
    pub domains: Vec<String>,
    pub has_exceptions: bool,
}

pub fn preset_rule(rules: &[Value], preset: &str) -> Option<PresetRule> {
    rules
        .iter()
        .find(|r| {
            name_of(r).starts_with(preset)
                || str_of(r, "Identity").is_some_and(|i| i.starts_with(preset))
        })
        .map(|r| PresetRule {
            enabled: rule_enabled(r),
            users: strs_of(r, "SentTo").len(),
            groups: strs_of(r, "SentToMemberOf").len(),
            domains: strs_of(r, "RecipientDomainIs"),
            has_exceptions: !strs_of(r, "ExceptIfSentTo").is_empty()
                || !strs_of(r, "ExceptIfSentToMemberOf").is_empty()
                || !strs_of(r, "ExceptIfRecipientDomainIs").is_empty(),
        })
}

impl PresetRule {
    /// A preset rule with no recipient conditions applies to everyone; one that names every
    /// customer domain does too.
    pub fn covers_all(&self, customer_domains: &[String]) -> bool {
        if !self.enabled {
            return false;
        }
        if self.users == 0 && self.groups == 0 && self.domains.is_empty() {
            return true;
        }
        self.users == 0
            && self.groups == 0
            && customer_domains
                .iter()
                .all(|d| self.domains.iter().any(|x| x.eq_ignore_ascii_case(d)))
    }

    pub fn is_scoped(&self) -> bool {
        self.enabled && (self.users > 0 || self.groups > 0 || !self.domains.is_empty())
    }

    pub fn describe(&self) -> String {
        if !self.enabled {
            return "disabled".to_string();
        }
        if self.users == 0 && self.groups == 0 && self.domains.is_empty() {
            return format!(
                "all recipients{}",
                if self.has_exceptions {
                    " with exceptions"
                } else {
                    ""
                }
            );
        }
        format!(
            "{} user(s), {} group(s), {} domain(s){}",
            self.users,
            self.groups,
            self.domains.len(),
            if self.has_exceptions {
                ", with exceptions"
            } else {
                ""
            }
        )
    }
}

pub fn evaluate_standard_preset(
    eop_rules: &[Value],
    atp_rules: Option<&[Value]>,
    customer_domains: &[String],
) -> (FindingStatus, String) {
    let eop_std = preset_rule(eop_rules, STANDARD);
    let eop_strict = preset_rule(eop_rules, STRICT);
    let atp_std = atp_rules.and_then(|r| preset_rule(r, STANDARD));
    let mut parts = Vec::new();
    let mut status = FindingStatus::Pass;

    match &eop_std {
        None => {
            status = FindingStatus::Fail;
            parts.push("Standard preset (EOP) is not enabled".to_string());
        }
        Some(r) if r.covers_all(customer_domains) => {
            parts.push(format!("Standard preset (EOP): {}", r.describe()))
        }
        Some(r) if r.enabled => {
            status = FindingStatus::Warning;
            parts.push(format!(
                "Standard preset (EOP) is scoped to {}",
                r.describe()
            ));
        }
        Some(r) => {
            status = FindingStatus::Fail;
            parts.push(format!("Standard preset (EOP) is {}", r.describe()));
        }
    }
    if atp_rules.is_some() {
        match &atp_std {
            None => {
                status = FindingStatus::Fail;
                parts.push("Standard preset (Defender for Office 365) is not enabled".to_string());
            }
            Some(r) if r.covers_all(customer_domains) => parts.push(format!(
                "Standard preset (Defender for Office 365): {}",
                r.describe()
            )),
            Some(r) if r.enabled => {
                if status == FindingStatus::Pass {
                    status = FindingStatus::Warning;
                }
                parts.push(format!(
                    "Standard preset (Defender for Office 365) is scoped to {}",
                    r.describe()
                ));
            }
            Some(r) => {
                status = FindingStatus::Fail;
                parts.push(format!(
                    "Standard preset (Defender for Office 365) is {}",
                    r.describe()
                ));
            }
        }
    }
    if let Some(s) = &eop_strict {
        parts.push(format!("Strict preset: {}", s.describe()));
    }
    (status, parts.join("; "))
}

pub fn antiphish_targets(policies: &[Value]) -> (usize, usize) {
    policies
        .iter()
        .filter(|p| bool_or(p, "Enabled", true))
        .fold((0, 0), |(u, d), p| {
            let users = if bool_or(p, "EnableTargetedUserProtection", false) {
                strs_of(p, "TargetedUsersToProtect").len()
            } else {
                0
            };
            let domains = if bool_or(p, "EnableTargetedDomainsProtection", false) {
                strs_of(p, "TargetedDomainsToProtect").len()
            } else {
                0
            };
            (u + users, d + domains)
        })
}

pub fn evaluate_strict_preset(
    eop_rules: &[Value],
    atp_rules: Option<&[Value]>,
    antiphish: Option<&[Value]>,
) -> (FindingStatus, String) {
    let strict = preset_rule(eop_rules, STRICT)
        .filter(|r| r.is_scoped())
        .or_else(|| {
            atp_rules
                .and_then(|r| preset_rule(r, STRICT))
                .filter(|r| r.is_scoped())
        });
    let (users, domains) = antiphish.map(antiphish_targets).unwrap_or((0, 0));
    match strict {
        Some(r) => (
            FindingStatus::Pass,
            format!(
                "Strict preset applied to {}; impersonation protection lists {} user(s) and {} domain(s)",
                r.describe(),
                users,
                domains
            ),
        ),
        None if users > 0 || domains > 0 => (
            FindingStatus::Pass,
            format!(
                "Strict preset not applied to a named group, but impersonation protection lists {} user(s) and {} domain(s)",
                users, domains
            ),
        ),
        None => (
            FindingStatus::Fail,
            "Strict preset is not applied to any users or groups and impersonation protection has no targeted users or domains"
                .to_string(),
        ),
    }
}

/// VIP users not named in the Strict preset rule. Returns (uncovered, strict has groups).
pub fn vips_not_in_strict(
    vips: &[Value],
    eop_rules: &[Value],
    atp_rules: Option<&[Value]>,
) -> (Vec<String>, bool, bool) {
    let rule = atp_rules
        .and_then(|r| r.iter().find(|x| name_of(x).starts_with(STRICT)))
        .or_else(|| eop_rules.iter().find(|x| name_of(x).starts_with(STRICT)));
    let Some(rule) = rule.filter(|r| rule_enabled(r)) else {
        return (vip_names(vips), false, false);
    };
    let sent_to: Vec<String> = strs_of(rule, "SentTo")
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let has_groups = !strs_of(rule, "SentToMemberOf").is_empty();
    let uncovered = vips
        .iter()
        .filter(|v| {
            let candidates = [
                str_of(v, "UserPrincipalName"),
                str_of(v, "WindowsEmailAddress"),
                str_of(v, "Identity"),
                str_of(v, "Name"),
            ];
            !candidates
                .iter()
                .flatten()
                .any(|c| sent_to.iter().any(|s| s == &c.to_ascii_lowercase()))
        })
        .map(|v| {
            str_of(v, "UserPrincipalName")
                .or_else(|| str_of(v, "Identity"))
                .unwrap_or("(unknown)")
                .to_string()
        })
        .collect();
    (uncovered, has_groups, true)
}

fn vip_names(vips: &[Value]) -> Vec<String> {
    vips.iter()
        .map(|v| {
            str_of(v, "UserPrincipalName")
                .or_else(|| str_of(v, "Identity"))
                .unwrap_or("(unknown)")
                .to_string()
        })
        .collect()
}

// ─── Runner ─────────────────────────────────────────────────────────────────

/// Fetch every Defender/EOP policy once and record all the checks that read them.
pub async fn run_all(
    exo: &Exo<'_>,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
    findings: &mut Vec<Finding>,
) {
    let mdo = has_mdo(tenant);
    let p2 = has_mdo_p2(tenant);
    let customer_domains: Vec<String> = tenant
        .verified_domains
        .iter()
        .filter(|d| crate::modules::exchange::dns::is_customer_domain(d))
        .cloned()
        .collect();

    let antiphish = exo.fetch("Get-AntiPhishPolicy", None).await;
    let outbound = exo.fetch("Get-HostedOutboundSpamFilterPolicy", None).await;
    let malware = exo.fetch("Get-MalwareFilterPolicy", None).await;
    let eop_rules = exo.fetch("Get-EOPProtectionPolicyRule", None).await;
    let atp_rules: Option<Fetched> = if mdo {
        Some(exo.fetch("Get-ATPProtectionPolicyRule", None).await)
    } else {
        None
    };
    let enabled_presets: Vec<String> = [STANDARD, STRICT]
        .iter()
        .filter(|preset| {
            let in_eop = eop_rules
                .as_deref()
                .ok()
                .and_then(|r| preset_rule(r, preset))
                .is_some_and(|r| r.enabled);
            let in_atp = atp_rules
                .as_ref()
                .and_then(|f| f.as_deref().ok())
                .and_then(|r| preset_rule(r, preset))
                .is_some_and(|r| r.enabled);
            in_eop || in_atp
        })
        .map(|s| s.to_string())
        .collect();

    // DEFENDER-ANTIPHISH-001
    record_one(
        findings,
        need(&antiphish).map(|p| {
            let (status, current) = evaluate_antiphish(p, mdo);
            finding(
                registry,
                "DEFENDER-ANTIPHISH-001",
                CATEGORY,
                SECTION_EOP,
                "Anti-Phishing Policy",
                "An anti-phishing policy with spoof intelligence, DMARC enforcement and (with Defender for Office 365) aggressive impersonation protection is in force",
            )
            .status(status)
            .current_value(current)
            .expected_value("Spoof intelligence and HonorDmarcPolicy on; PhishThresholdLevel >= 2, mailbox intelligence, targeted user/domain protection with Quarantine actions and all safety tips on")
            .remediation(
                "Defender portal > Email & collaboration > Policies & rules > Threat policies > Anti-phishing: edit the default policy \
                 (or enable the Standard/Strict preset) with phishing threshold Aggressive, impersonation protection for users and domains, \
                 mailbox intelligence with Quarantine, all safety tips, and Honor DMARC policy.",
            )
            .build()
        }),
        "DEFENDER-ANTIPHISH-001",
        CATEGORY,
        SECTION_EOP,
        "Anti-Phishing Policy",
    );

    // DEFENDER-ANTISPAM-001
    record_one(
        findings,
        need(&outbound).map(|p| {
            let (status, current) = evaluate_outbound_notifications(p);
            finding(
                registry,
                "DEFENDER-ANTISPAM-001",
                CATEGORY,
                SECTION_EOP,
                "Outbound Spam Notifications",
                "The outbound spam policy notifies administrators and copies suspicious outbound mail",
            )
            .status(status)
            .current_value(current)
            .expected_value("BccSuspiciousOutboundMail and NotifyOutboundSpam on with recipients set")
            .remediation(
                "Set-HostedOutboundSpamFilterPolicy -Identity Default -BccSuspiciousOutboundMail $true \
                 -BccSuspiciousOutboundAdditionalRecipients <mailbox> -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients <mailbox>",
            )
            .build()
        }),
        "DEFENDER-ANTISPAM-001",
        CATEGORY,
        SECTION_EOP,
        "Outbound Spam Notifications",
    );

    // DEFENDER-OUTBOUND-001
    record_one(
        findings,
        need(&outbound).map(|p| {
            let (status, current) = evaluate_outbound_limits(p);
            finding(
                registry,
                "DEFENDER-OUTBOUND-001",
                CATEGORY,
                SECTION_EOP,
                "Outbound Message Limits",
                "Outbound recipient limits are set and users who exceed them are blocked",
            )
            .status(status)
            .current_value(current)
            .expected_value("External/hour <= 500, internal/hour <= 1000, per day <= 1000, ActionWhenThresholdReached = BlockUser")
            .remediation(
                "Set-HostedOutboundSpamFilterPolicy -Identity Default -RecipientLimitExternalPerHour 500 \
                 -RecipientLimitInternalPerHour 1000 -RecipientLimitPerDay 1000 -ActionWhenThresholdReached BlockUser",
            )
            .build()
        }),
        "DEFENDER-OUTBOUND-001",
        CATEGORY,
        SECTION_EOP,
        "Outbound Message Limits",
    );

    // DEFENDER-ANTIMALWARE-001
    record_one(
        findings,
        need(&malware).map(|p| {
            let (status, current, affected) = evaluate_file_filter(p);
            let mut f = finding(
                registry,
                "DEFENDER-ANTIMALWARE-001",
                CATEGORY,
                SECTION_EOP,
                "Common Attachment Types Filter",
                "Every anti-malware policy blocks common executable attachment types",
            )
            .status(status)
            .current_value(current)
            .expected_value("EnableFileFilter = True on every anti-malware policy")
            .remediation("Set-MalwareFilterPolicy -Identity <policy> -EnableFileFilter $true (Defender portal > Anti-malware > policy > Enable the common attachments filter).");
            if !affected.is_empty() {
                f = f.affected_resources(affected);
            }
            f.build()
        }),
        "DEFENDER-ANTIMALWARE-001",
        CATEGORY,
        SECTION_EOP,
        "Common Attachment Types Filter",
    );

    // DEFENDER-ANTIMALWARE-002
    record_one(
        findings,
        need(&malware).map(|p| {
            let (status, current) = evaluate_internal_malware_notifications(p);
            finding(
                registry,
                "DEFENDER-ANTIMALWARE-002",
                CATEGORY,
                SECTION_EOP,
                "Internal Sender Malware Notifications",
                "Administrators are notified when an internal user sends malware",
            )
            .status(status)
            .current_value(current)
            .expected_value("EnableInternalSenderAdminNotifications = True with InternalSenderAdminAddress set")
            .remediation("Set-MalwareFilterPolicy -Identity Default -EnableInternalSenderAdminNotifications $true -InternalSenderAdminAddress <mailbox>")
            .build()
        }),
        "DEFENDER-ANTIMALWARE-002",
        CATEGORY,
        SECTION_EOP,
        "Internal Sender Malware Notifications",
    );

    // DEFENDER-MALWARE-002
    record_one(
        findings,
        need(&malware).map(|p| {
            let (status, current) = evaluate_blocked_types(p);
            finding(
                registry,
                "DEFENDER-MALWARE-002",
                CATEGORY,
                SECTION_EOP,
                "Comprehensive Attachment Filtering",
                "The common attachments filter blocks the full list of high-risk file types",
            )
            .status(status)
            .current_value(current)
            .expected_value(format!("FileTypes includes all {} high-risk extensions in the CIS list", CORE_BLOCKED_TYPES.len()))
            .remediation(
                "Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true -FileTypes <CIS 2.1.11 list>; the Defender portal \
                 anti-malware policy editor lets you add the missing extensions under Common attachments filter.",
            )
            .build()
        }),
        "DEFENDER-MALWARE-002",
        CATEGORY,
        SECTION_EOP,
        "Comprehensive Attachment Filtering",
    );

    // DEFENDER-SAFELINKS-001
    if !mdo {
        findings.push(not_licensed(
            registry,
            "DEFENDER-SAFELINKS-001",
            SECTION_MDO,
            "Safe Links",
            "Safe Links rewrites and scans URLs in email, Teams and Office",
            "Defender for Office 365 Plan 1 (ATP_ENTERPRISE)",
        ));
    } else {
        let policies = exo.fetch("Get-SafeLinksPolicy", None).await;
        let rules = exo.fetch("Get-SafeLinksRule", None).await;
        record_one(
            findings,
            need(&policies).map(|p| {
                let r = rules.as_deref().unwrap_or(&[]);
                let (status, current) = evaluate_safelinks(p, r, &enabled_presets);
                finding(
                    registry,
                    "DEFENDER-SAFELINKS-001",
                    CATEGORY,
                    SECTION_MDO,
                    "Safe Links",
                    "Safe Links rewrites and scans URLs in email, Teams and Office",
                )
                .status(status)
                .current_value(current)
                .expected_value("An applied policy with Safe Links on for email, Teams and Office, click tracking, no click-through, URL scanning and internal senders")
                .remediation(
                    "Enable the Standard or Strict preset security policy for all recipients, or edit the Safe Links policy in \
                     Defender portal > Threat policies > Safe Links to turn on every protection setting and disable click-through.",
                )
                .build()
            }),
            "DEFENDER-SAFELINKS-001",
            CATEGORY,
            SECTION_MDO,
            "Safe Links",
        );
    }

    // DEFENDER-SAFEATTACH-001 / 002
    if !mdo {
        for (id, setting, desc) in [
            (
                "DEFENDER-SAFEATTACH-001",
                "Safe Attachments",
                "Safe Attachments detonates email attachments before delivery",
            ),
            (
                "DEFENDER-SAFEATTACH-002",
                "Safe Attachments for SharePoint, OneDrive and Teams",
                "Safe Attachments scans files in SharePoint, OneDrive and Teams",
            ),
        ] {
            findings.push(not_licensed(
                registry,
                id,
                SECTION_MDO,
                setting,
                desc,
                "Defender for Office 365 Plan 1 (ATP_ENTERPRISE)",
            ));
        }
    } else {
        let policies = exo.fetch("Get-SafeAttachmentPolicy", None).await;
        let rules = exo.fetch("Get-SafeAttachmentRule", None).await;
        record_one(
            findings,
            need(&policies).map(|p| {
                let r = rules.as_deref().unwrap_or(&[]);
                let (status, current) = evaluate_safeattachments(p, r, &enabled_presets);
                finding(
                    registry,
                    "DEFENDER-SAFEATTACH-001",
                    CATEGORY,
                    SECTION_MDO,
                    "Safe Attachments",
                    "Safe Attachments detonates email attachments before delivery",
                )
                .status(status)
                .current_value(current)
                .expected_value("An applied Safe Attachments policy with Enable = True and Action Block or DynamicDelivery")
                .remediation(
                    "Enable the Standard or Strict preset for all recipients, or create a Safe Attachments policy \
                     (Defender portal > Threat policies > Safe Attachments) with action Block and apply it to all domains.",
                )
                .build()
            }),
            "DEFENDER-SAFEATTACH-001",
            CATEGORY,
            SECTION_MDO,
            "Safe Attachments",
        );

        let atp = exo.fetch("Get-AtpPolicyForO365", None).await;
        record_one(
            findings,
            need(&atp).and_then(|rows| {
                let policy = rows.first().ok_or_else(|| anyhow::anyhow!("Get-AtpPolicyForO365 returned no rows"))?;
                let (status, current) = evaluate_atp_global(policy, p2);
                Ok(finding(
                    registry,
                    "DEFENDER-SAFEATTACH-002",
                    CATEGORY,
                    SECTION_MDO,
                    "Safe Attachments for SharePoint, OneDrive and Teams",
                    "Safe Attachments scans files in SharePoint, OneDrive and Teams, and Safe Documents is on",
                )
                .status(status)
                .current_value(current)
                .expected_value("EnableATPForSPOTeamsODB = True; with Plan 2 EnableSafeDocs = True and AllowSafeDocsOpen = False")
                .remediation("Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true -EnableSafeDocs $true -AllowSafeDocsOpen $false")
                .build())
            }),
            "DEFENDER-SAFEATTACH-002",
            CATEGORY,
            SECTION_MDO,
            "Safe Attachments for SharePoint, OneDrive and Teams",
        );
    }

    // DEFENDER-ZAP-001 (Teams)
    if !p2 {
        findings.push(not_licensed(
            registry,
            "DEFENDER-ZAP-001",
            SECTION_MDO,
            "Zero-hour Auto Purge for Teams",
            "Zero-hour auto purge removes malicious messages already delivered to Teams",
            "Defender for Office 365 Plan 2 (THREAT_INTELLIGENCE)",
        ));
    } else {
        let teams = exo.fetch("Get-TeamsProtectionPolicy", None).await;
        record_one(
            findings,
            need(&teams).and_then(|rows| {
                let p = rows.first().ok_or_else(|| anyhow::anyhow!("Get-TeamsProtectionPolicy returned no rows"))?;
                let zap = bool_or(p, "ZapEnabled", false);
                Ok(finding(
                    registry,
                    "DEFENDER-ZAP-001",
                    CATEGORY,
                    SECTION_MDO,
                    "Zero-hour Auto Purge for Teams",
                    "Zero-hour auto purge removes malicious messages already delivered to Teams",
                )
                .status(if zap { FindingStatus::Pass } else { FindingStatus::Fail })
                .current_value(format!("Get-TeamsProtectionPolicy ZapEnabled = {}", zap))
                .expected_value("ZapEnabled = True")
                .remediation("Set-TeamsProtectionPolicy -ZapEnabled $true (Defender portal > Settings > Email & collaboration > Microsoft Teams protection).")
                .build())
            }),
            "DEFENDER-ZAP-001",
            CATEGORY,
            SECTION_MDO,
            "Zero-hour Auto Purge for Teams",
        );
    }

    // DEFENDER-PRESET-001
    record_one(
        findings,
        need(&eop_rules).map(|eop| {
            let atp = atp_rules.as_ref().and_then(|f| f.as_deref().ok());
            let (status, current) = evaluate_standard_preset(eop, atp, &customer_domains);
            finding(
                registry,
                "DEFENDER-PRESET-001",
                CATEGORY,
                SECTION_EOP,
                "Standard Preset Security Policy Coverage",
                "The Standard preset security policy is enabled and applies to all recipients",
            )
            .status(status)
            .current_value(current)
            .expected_value("Standard preset rule enabled with no recipient conditions (EOP and, when licensed, Defender for Office 365)")
            .remediation(
                "Defender portal > Email & collaboration > Policies & rules > Threat policies > Preset security policies > \
                 Standard protection > Manage: enable it and choose All recipients for both EOP and Defender for Office 365 protections.",
            )
            .build()
        }),
        "DEFENDER-PRESET-001",
        CATEGORY,
        SECTION_EOP,
        "Standard Preset Security Policy Coverage",
    );

    // DEFENDER-PRESET-002
    record_one(
        findings,
        need(&eop_rules).map(|eop| {
            let atp = atp_rules.as_ref().and_then(|f| f.as_deref().ok());
            let ap = antiphish.as_deref().ok();
            let (status, current) = evaluate_strict_preset(eop, atp, ap);
            finding(
                registry,
                "DEFENDER-PRESET-002",
                CATEGORY,
                SECTION_EOP,
                "Strict Preset or Impersonation Protection for High-Value Users",
                "High-value users get Strict preset protection or are listed in impersonation protection",
            )
            .status(status)
            .current_value(current)
            .expected_value("Strict preset applied to named users or groups, or anti-phishing impersonation protection lists executives and partner domains")
            .remediation(
                "Preset security policies > Strict protection: apply to executives, finance, payroll and administrators (or a group). \
                 In the anti-phishing policy add those users under Impersonation > Users to protect and key partner domains under Domains to protect.",
            )
            .build()
        }),
        "DEFENDER-PRESET-002",
        CATEGORY,
        SECTION_EOP,
        "Strict Preset or Impersonation Protection for High-Value Users",
    );

    // Priority accounts (Plan 2)
    if !p2 {
        for (id, setting, desc) in [
            (
                "DEFENDER-PRIORITY-001",
                "Priority Account Protection",
                "Priority account protection is enabled",
            ),
            (
                "DEFENDER-PRIORITY-002",
                "Strict Protection for Priority Accounts",
                "Priority accounts are covered by the Strict preset",
            ),
            (
                "DEFENDER-PRIORITY-003",
                "Priority Account Tagging",
                "High-value users are tagged as priority accounts",
            ),
        ] {
            findings.push(not_licensed(
                registry,
                id,
                SECTION_MDO,
                setting,
                desc,
                "Defender for Office 365 Plan 2 (THREAT_INTELLIGENCE)",
            ));
        }
        return;
    }
    let tenant_settings = exo.fetch("Get-EmailTenantSettings", None).await;
    let vips = exo
        .fetch(
            "Get-User",
            Some(json!({"IsVIP": true, "ResultSize": "Unlimited"})),
        )
        .await;

    record_one(
        findings,
        need(&tenant_settings).and_then(|rows| {
            let s = rows.first().ok_or_else(|| anyhow::anyhow!("Get-EmailTenantSettings returned no rows"))?;
            let on = bool_or(s, "EnablePriorityAccountProtection", false);
            Ok(finding(
                registry,
                "DEFENDER-PRIORITY-001",
                CATEGORY,
                SECTION_MDO,
                "Priority Account Protection",
                "Priority account protection is enabled so tagged accounts get differentiated protection and alerts",
            )
            .status(if on { FindingStatus::Pass } else { FindingStatus::Fail })
            .current_value(format!("EnablePriorityAccountProtection = {}", on))
            .expected_value("EnablePriorityAccountProtection = True")
            .remediation("Set-EmailTenantSettings -EnablePriorityAccountProtection $true (Defender portal > Settings > Email & collaboration > Priority account protection).")
            .build())
        }),
        "DEFENDER-PRIORITY-001",
        CATEGORY,
        SECTION_MDO,
        "Priority Account Protection",
    );

    record_one(
        findings,
        need(&vips).map(|v| {
            let names = vip_names(v);
            let mut f = finding(
                registry,
                "DEFENDER-PRIORITY-003",
                CATEGORY,
                SECTION_MDO,
                "Priority Account Tagging",
                "Executives, finance, payroll and administrators are tagged as priority accounts",
            )
            .status(if names.is_empty() { FindingStatus::Warning } else { FindingStatus::Pass })
            .current_value(if names.is_empty() {
                "No user is tagged as a priority account (Get-User -IsVIP returned none)".to_string()
            } else {
                format!("{} priority account(s): {}", names.len(), list_preview(&names, 10))
            })
            .expected_value("At least the high-value users carry the Priority account tag")
            .remediation("Microsoft 365 admin center > Setup > Organizational knowledge > Priority accounts (or Set-User <upn> -VIP $true).");
            if !names.is_empty() {
                f = f.affected_resources(names);
            }
            f.build()
        }),
        "DEFENDER-PRIORITY-003",
        CATEGORY,
        SECTION_MDO,
        "Priority Account Tagging",
    );

    record_one(
        findings,
        match (need(&vips), need(&eop_rules)) {
            (Ok(v), Ok(eop)) => {
                let atp = atp_rules.as_ref().and_then(|f| f.as_deref().ok());
                let (uncovered, has_groups, strict_enabled) = vips_not_in_strict(v, eop, atp);
                let (status, current) = if v.is_empty() {
                    (FindingStatus::Warning, "No priority accounts are tagged, so nothing is covered by Strict protection".to_string())
                } else if !strict_enabled {
                    (
                        FindingStatus::Fail,
                        format!(
                            "{} priority account(s) tagged but the Strict preset is not enabled",
                            v.len()
                        ),
                    )
                } else if uncovered.is_empty() {
                    (
                        FindingStatus::Pass,
                        format!(
                            "All {} priority account(s) are named in the Strict preset rule",
                            v.len()
                        ),
                    )
                } else if has_groups {
                    (
                        FindingStatus::Warning,
                        format!(
                            "{} of {} priority account(s) are not named directly in the Strict preset rule; it targets groups whose membership was not expanded: {}",
                            uncovered.len(),
                            v.len(),
                            list_preview(&uncovered, 10)
                        ),
                    )
                } else {
                    (
                        FindingStatus::Fail,
                        format!(
                            "{} of {} priority account(s) are not covered by the Strict preset: {}",
                            uncovered.len(),
                            v.len(),
                            list_preview(&uncovered, 10)
                        ),
                    )
                };
                let mut f = finding(
                    registry,
                    "DEFENDER-PRIORITY-002",
                    CATEGORY,
                    SECTION_MDO,
                    "Strict Protection for Priority Accounts",
                    "Every priority account is covered by the Strict preset security policy",
                )
                .status(status)
                .current_value(current)
                .expected_value("Strict preset rule enabled and its recipients include every priority account")
                .remediation("Preset security policies > Strict protection > Manage: add the priority accounts (or their group) to the recipients.");
                if !uncovered.is_empty() {
                    f = f.affected_resources(uncovered);
                }
                Ok(f.build())
            }
            (Err(e), _) | (_, Err(e)) => Err(e),
        },
        "DEFENDER-PRIORITY-002",
        CATEGORY,
        SECTION_MDO,
        "Strict Protection for Priority Accounts",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_antiphish(name: &str, default: bool) -> Value {
        json!({
            "Name": name, "IsDefault": default, "Enabled": true,
            "EnableSpoofIntelligence": true, "HonorDmarcPolicy": true, "PhishThresholdLevel": 3,
            "EnableMailboxIntelligence": true, "EnableMailboxIntelligenceProtection": true,
            "EnableTargetedUserProtection": true, "EnableOrganizationDomainsProtection": true,
            "EnableFirstContactSafetyTips": true, "EnableSimilarUsersSafetyTips": true,
            "EnableSimilarDomainsSafetyTips": true, "EnableUnusualCharactersSafetyTips": true,
            "TargetedUserProtectionAction": "Quarantine", "TargetedDomainProtectionAction": "Quarantine",
            "MailboxIntelligenceProtectionAction": "Quarantine",
            "TargetedUsersToProtect": ["CEO;ceo@contoso.com"], "TargetedDomainsToProtect": ["partner.example"],
            "EnableTargetedDomainsProtection": true
        })
    }

    #[test]
    fn antiphish_full_policy_passes_and_default_policy_gaps_fail() {
        let (s, _) = evaluate_antiphish(
            &[full_antiphish("Strict Preset Security Policy1", false)],
            true,
        );
        assert_eq!(s, FindingStatus::Pass);
        let weak = json!({"Name": "Office365 AntiPhish Default", "IsDefault": true, "Enabled": true,
                          "EnableSpoofIntelligence": true, "HonorDmarcPolicy": true, "PhishThresholdLevel": 1});
        let (s, _) = evaluate_antiphish(std::slice::from_ref(&weak), true);
        assert_eq!(s, FindingStatus::Fail);
        // EOP-only tenants are judged on spoof intelligence and DMARC alone.
        let (s, _) = evaluate_antiphish(&[weak], false);
        assert_eq!(s, FindingStatus::Pass);
        assert_eq!(evaluate_antiphish(&[], true).0, FindingStatus::Fail);
    }

    #[test]
    fn outbound_limits_and_notifications() {
        let good = json!({"Name": "Default", "IsDefault": true, "RecipientLimitExternalPerHour": 500,
            "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser",
            "BccSuspiciousOutboundMail": true, "BccSuspiciousOutboundAdditionalRecipients": ["soc@contoso.com"],
            "NotifyOutboundSpam": true, "NotifyOutboundSpamRecipients": ["soc@contoso.com"]});
        assert_eq!(
            evaluate_outbound_limits(std::slice::from_ref(&good)).0,
            FindingStatus::Pass
        );
        assert_eq!(
            evaluate_outbound_notifications(&[good]).0,
            FindingStatus::Pass
        );
        let defaults = json!({"Name": "Default", "IsDefault": true, "RecipientLimitExternalPerHour": 0,
            "RecipientLimitInternalPerHour": 0, "RecipientLimitPerDay": 0, "ActionWhenThresholdReached": "BlockUserForToday",
            "BccSuspiciousOutboundMail": false, "NotifyOutboundSpam": false});
        assert_eq!(
            evaluate_outbound_limits(std::slice::from_ref(&defaults)).0,
            FindingStatus::Fail
        );
        assert_eq!(
            evaluate_outbound_notifications(&[defaults]).0,
            FindingStatus::Fail
        );
    }

    #[test]
    fn malware_file_filter_and_blocked_types() {
        let all: Vec<&str> = CORE_BLOCKED_TYPES.to_vec();
        let full = json!({"Name": "Default", "IsDefault": true, "EnableFileFilter": true, "FileTypes": all,
                          "EnableInternalSenderAdminNotifications": true, "InternalSenderAdminAddress": "soc@contoso.com"});
        assert_eq!(
            evaluate_file_filter(std::slice::from_ref(&full)).0,
            FindingStatus::Pass
        );
        assert_eq!(
            evaluate_blocked_types(std::slice::from_ref(&full)).0,
            FindingStatus::Pass
        );
        assert_eq!(
            evaluate_internal_malware_notifications(&[full]).0,
            FindingStatus::Pass
        );

        let few = json!({"Name": "Default", "IsDefault": true, "EnableFileFilter": true, "FileTypes": ["exe", "bat"]});
        assert_eq!(evaluate_blocked_types(&[few]).0, FindingStatus::Fail);
        let most: Vec<&str> = CORE_BLOCKED_TYPES[..CORE_BLOCKED_TYPES.len() - 3].to_vec();
        let nearly = json!({"Name": "Default", "IsDefault": true, "EnableFileFilter": true, "FileTypes": most});
        assert_eq!(evaluate_blocked_types(&[nearly]).0, FindingStatus::Warning);
        let off = json!({"Name": "Custom", "EnableFileFilter": false});
        let (s, _, affected) = evaluate_file_filter(&[off]);
        assert_eq!(s, FindingStatus::Fail);
        assert_eq!(affected, vec!["Custom"]);
    }

    #[test]
    fn safelinks_requires_an_applied_policy() {
        let good = json!({"Name": "Corp", "EnableSafeLinksForEmail": true, "EnableSafeLinksForTeams": true,
            "EnableSafeLinksForOffice": true, "TrackClicks": true, "AllowClickThrough": false, "ScanUrls": true,
            "EnableForInternalSenders": true, "DeliverMessageAfterScan": true, "DisableUrlRewrite": false});
        let rule_on = json!({"Name": "Corp", "SafeLinksPolicy": "Corp", "State": "Enabled"});
        let rule_off = json!({"Name": "Corp", "SafeLinksPolicy": "Corp", "State": "Disabled"});
        assert_eq!(
            evaluate_safelinks(std::slice::from_ref(&good), &[rule_on], &[]).0,
            FindingStatus::Pass
        );
        assert_eq!(
            evaluate_safelinks(std::slice::from_ref(&good), &[rule_off], &[]).0,
            FindingStatus::Fail
        );
        // Preset policies carry a numeric suffix and are applied through the preset rule.
        let mut preset = good.clone();
        preset["Name"] = json!("Standard Preset Security Policy1659");
        assert_eq!(
            evaluate_safelinks(&[preset], &[], &[STANDARD.to_string()]).0,
            FindingStatus::Pass
        );
    }

    #[test]
    fn safeattachments_and_atp_global() {
        let p = json!({"Name": "Corp", "Enable": true, "Action": "Block"});
        let r = json!({"Name": "Corp", "SafeAttachmentPolicy": "Corp", "State": "Enabled"});
        assert_eq!(
            evaluate_safeattachments(std::slice::from_ref(&p), &[r], &[]).0,
            FindingStatus::Pass
        );
        assert_eq!(
            evaluate_safeattachments(&[p], &[], &[]).0,
            FindingStatus::Fail
        );
        let atp = json!({"EnableATPForSPOTeamsODB": true, "EnableSafeDocs": false, "AllowSafeDocsOpen": true});
        assert_eq!(evaluate_atp_global(&atp, false).0, FindingStatus::Pass);
        assert_eq!(evaluate_atp_global(&atp, true).0, FindingStatus::Fail);
    }

    #[test]
    fn preset_rules_cover_all_or_are_scoped() {
        let domains = vec!["contoso.com".to_string()];
        let eop_all = vec![json!({"Name": "Standard Preset Security Policy", "State": "Enabled"})];
        let (s, _) = evaluate_standard_preset(&eop_all, None, &domains);
        assert_eq!(s, FindingStatus::Pass);

        let eop_scoped = vec![
            json!({"Name": "Standard Preset Security Policy", "State": "Enabled", "SentToMemberOf": ["Pilot"]}),
        ];
        assert_eq!(
            evaluate_standard_preset(&eop_scoped, None, &domains).0,
            FindingStatus::Warning
        );

        let eop_domain = vec![
            json!({"Name": "Standard Preset Security Policy", "State": "Enabled", "RecipientDomainIs": ["contoso.com"]}),
        ];
        assert_eq!(
            evaluate_standard_preset(&eop_domain, None, &domains).0,
            FindingStatus::Pass
        );

        // Licensed for MDO but the ATP rule is missing: Fail.
        assert_eq!(
            evaluate_standard_preset(&eop_all, Some(&[]), &domains).0,
            FindingStatus::Fail
        );
        assert_eq!(
            evaluate_standard_preset(&[], None, &domains).0,
            FindingStatus::Fail
        );
    }

    #[test]
    fn strict_preset_or_impersonation_targets() {
        let strict = vec![
            json!({"Name": "Strict Preset Security Policy", "State": "Enabled", "SentToMemberOf": ["Execs"]}),
        ];
        assert_eq!(
            evaluate_strict_preset(&strict, None, None).0,
            FindingStatus::Pass
        );
        let none: Vec<Value> = vec![];
        assert_eq!(
            evaluate_strict_preset(&none, None, None).0,
            FindingStatus::Fail
        );
        let ap = vec![full_antiphish("Default", true)];
        assert_eq!(
            evaluate_strict_preset(&none, None, Some(&ap)).0,
            FindingStatus::Pass
        );
    }

    #[test]
    fn vip_coverage_by_strict_rule() {
        let vips = vec![
            json!({"UserPrincipalName": "ceo@contoso.com"}),
            json!({"UserPrincipalName": "cfo@contoso.com"}),
        ];
        let rules = vec![
            json!({"Name": "Strict Preset Security Policy", "State": "Enabled", "SentTo": ["CEO@contoso.com"]}),
        ];
        let (uncovered, groups, enabled) = vips_not_in_strict(&vips, &rules, None);
        assert_eq!(uncovered, vec!["cfo@contoso.com"]);
        assert!(!groups);
        assert!(enabled);
        let (uncovered, _, enabled) = vips_not_in_strict(&vips, &[], None);
        assert_eq!(uncovered.len(), 2);
        assert!(!enabled);
    }
}
