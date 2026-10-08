//! Pure evaluators over Intune JSON: compliance, enrolment, multi-admin approval, update rings, and the
//! settings-catalog parsing behind the ASR, macro, App Control, encryption and baseline checks. Nothing
//! here touches the network, so every rule has a fixture test.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde_json::Value;

use crate::assessment::finding::FindingStatus;

pub type Outcome = Result<(FindingStatus, String)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Platform {
    Windows,
    IOs,
    Android,
    MacOs,
    Linux,
}

impl Platform {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::IOs => "iOS/iPadOS",
            Self::Android => "Android",
            Self::MacOs => "macOS",
            Self::Linux => "Linux",
        }
    }

    /// From `managedDevice.operatingSystem` or an `@odata.type` / `platforms` string.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.to_ascii_lowercase();
        if s.contains("windows") {
            Some(Self::Windows)
        } else if s.contains("ios") || s.contains("ipados") {
            Some(Self::IOs)
        } else if s.contains("android") || s.contains("aosp") {
            Some(Self::Android)
        } else if s.contains("macos") || s.contains("mac os") {
            Some(Self::MacOs)
        } else if s.contains("linux") || s.contains("ubuntu") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

fn odata_type(v: &Value) -> &str {
    v.get("@odata.type").and_then(|t| t.as_str()).unwrap_or("")
}

fn is_assigned(v: &Value) -> bool {
    v.get("assignments")
        .and_then(|a| a.as_array())
        .is_some_and(|a| !a.is_empty())
}

fn name_of(v: &Value) -> &str {
    v.get("displayName")
        .or_else(|| v.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("(unnamed)")
}

/// Platforms with at least one managed device.
pub fn platforms_in_use(devices: &[Value]) -> BTreeMap<Platform, usize> {
    let mut out = BTreeMap::new();
    for d in devices {
        if let Some(p) = d
            .get("operatingSystem")
            .and_then(|o| o.as_str())
            .and_then(Platform::parse)
        {
            *out.entry(p).or_insert(0) += 1;
        }
    }
    out
}

/// INTUNE-COMPLIANCE-001: at least one assigned compliance policy for every platform in use.
/// `classic` is `deviceCompliancePolicies?$expand=assignments`; `catalog` the settings-catalog
/// `compliancePolicies` (Linux and newer Windows policies), which may be empty.
pub fn compliance_001(classic: &[Value], catalog: &[Value], devices: &[Value]) -> Outcome {
    let mut covered: BTreeSet<Platform> = BTreeSet::new();
    let mut assigned = 0;
    for p in classic.iter().filter(|p| is_assigned(p)) {
        assigned += 1;
        if let Some(plat) = Platform::parse(odata_type(p)) {
            covered.insert(plat);
        }
    }
    for p in catalog.iter().filter(|p| is_assigned(p)) {
        assigned += 1;
        if let Some(plat) = p
            .get("platforms")
            .and_then(|s| s.as_str())
            .and_then(Platform::parse)
        {
            covered.insert(plat);
        }
    }
    let in_use = platforms_in_use(devices);
    if assigned == 0 {
        return Ok((
            FindingStatus::Fail,
            format!(
                "{} compliance policies, none assigned",
                classic.len() + catalog.len()
            ),
        ));
    }
    let uncovered: Vec<String> = in_use
        .iter()
        .filter(|(p, _)| !covered.contains(p))
        .map(|(p, n)| format!("{} ({n} devices)", p.label()))
        .collect();
    let covered_text = covered
        .iter()
        .map(|p| p.label())
        .collect::<Vec<_>>()
        .join(", ");
    if in_use.is_empty() {
        return Ok((
            FindingStatus::Pass,
            format!("{assigned} assigned policies covering {covered_text}; no managed devices enrolled yet"),
        ));
    }
    if uncovered.is_empty() {
        Ok((
            FindingStatus::Pass,
            format!("{assigned} assigned policies covering {covered_text}"),
        ))
    } else {
        Ok((
            FindingStatus::Warning,
            format!(
                "Platforms without an assigned compliance policy: {}",
                uncovered.join(", ")
            ),
        ))
    }
}

/// INTUNE-COMPLIANCE-002: devices with no compliance policy are marked not compliant.
pub fn compliance_002(settings: &Value) -> Outcome {
    let secure = settings
        .get("secureByDefault")
        .and_then(|b| b.as_bool())
        .ok_or_else(|| {
            anyhow::anyhow!("deviceManagement/settings did not include secureByDefault")
        })?;
    Ok(if secure {
        (
            FindingStatus::Pass,
            "Devices with no compliance policy are marked Not compliant".to_string(),
        )
    } else {
        (
            FindingStatus::Fail,
            "Devices with no compliance policy are marked Compliant".to_string(),
        )
    })
}

const RESTRICTION_KEYS: [(&str, &str); 6] = [
    ("windowsRestriction", "Windows"),
    ("iosRestriction", "iOS/iPadOS"),
    ("androidRestriction", "Android device administrator"),
    ("androidForWorkRestriction", "Android Enterprise"),
    ("macOSRestriction", "macOS"),
    ("macRestriction", "macOS"),
];

/// INTUNE-ENROLL-001: the default platform restrictions block personally owned devices.
pub fn enroll_001(configs: &[Value]) -> Outcome {
    let default = configs
        .iter()
        .filter(|c| odata_type(c).ends_with("deviceEnrollmentPlatformRestrictionsConfiguration"))
        .min_by_key(|c| {
            c.get("priority")
                .and_then(|p| p.as_i64())
                .unwrap_or(i64::MAX)
        })
        .ok_or_else(|| {
            anyhow::anyhow!("no deviceEnrollmentPlatformRestrictionsConfiguration returned")
        })?;
    let mut allowed = Vec::new();
    let mut blocked = Vec::new();
    for (key, label) in RESTRICTION_KEYS {
        let Some(r) = default.get(key).filter(|r| r.is_object()) else {
            continue;
        };
        let platform_blocked = r
            .get("platformBlocked")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let personal_blocked = r
            .get("personalDeviceEnrollmentBlocked")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        if platform_blocked || personal_blocked {
            if !blocked.contains(&label) {
                blocked.push(label);
            }
        } else if !allowed.contains(&label) {
            allowed.push(label);
        }
    }
    if allowed.is_empty() && blocked.is_empty() {
        anyhow::bail!("default platform restrictions carried no per-platform settings");
    }
    Ok(if allowed.is_empty() {
        (
            FindingStatus::Pass,
            format!("Personal devices blocked for {}", blocked.join(", ")),
        )
    } else if blocked.is_empty() {
        (
            FindingStatus::Fail,
            format!("Personal devices allowed for {}", allowed.join(", ")),
        )
    } else {
        (
            FindingStatus::Warning,
            format!("Personal devices still allowed for {}", allowed.join(", ")),
        )
    })
}

const APPROVAL_REQUIRED: [&str; 5] = [
    "deviceWipe",
    "deviceRetire",
    "deviceDelete",
    "script",
    "app",
];

/// INTUNE-MULTIAPPROVAL-001: approval policies with approvers cover wipe, retire, delete, scripts and apps.
pub fn multiapproval_001(policies: &[Value]) -> Outcome {
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    let mut without_approvers = 0;
    for p in policies {
        let ty = p.get("policyType").and_then(|t| t.as_str()).unwrap_or("");
        let has_approvers = p
            .get("approverGroupIds")
            .and_then(|a| a.as_array())
            .is_some_and(|a| !a.is_empty());
        if !has_approvers {
            without_approvers += 1;
            continue;
        }
        if ty.eq_ignore_ascii_case("deviceAction") {
            covered.extend(["deviceWipe", "deviceRetire", "deviceDelete"]);
        }
        for req in APPROVAL_REQUIRED {
            if ty.eq_ignore_ascii_case(req) {
                covered.insert(req);
            }
        }
    }
    let missing: Vec<&str> = APPROVAL_REQUIRED
        .iter()
        .copied()
        .filter(|r| !covered.contains(r))
        .collect();
    if policies.is_empty() {
        return Ok((
            FindingStatus::Fail,
            "No multi-admin approval policies".to_string(),
        ));
    }
    let mut note = String::new();
    if without_approvers > 0 {
        note = format!("; {without_approvers} policies have no approver group");
    }
    Ok(if missing.is_empty() {
        (
            FindingStatus::Pass,
            format!(
                "Approval required for {}{note}",
                APPROVAL_REQUIRED.join(", ")
            ),
        )
    } else if covered.is_empty() {
        (
            FindingStatus::Fail,
            format!(
                "{} policies but none protect {}{note}",
                policies.len(),
                missing.join(", ")
            ),
        )
    } else {
        (
            FindingStatus::Warning,
            format!("Not covered: {}{note}", missing.join(", ")),
        )
    })
}

/// INTUNE-UPDATE-001: an assigned update ring defers quality updates 7 days or less and feature updates 30
/// or less with deadlines set, or Windows Autopatch manages updates.
pub fn update_001(device_configs: &[Value]) -> Outcome {
    let rings: Vec<&Value> = device_configs
        .iter()
        .filter(|c| odata_type(c).ends_with("windowsUpdateForBusinessConfiguration"))
        .collect();
    let assigned: Vec<&Value> = rings.iter().copied().filter(|r| is_assigned(r)).collect();
    if assigned
        .iter()
        .any(|r| name_of(r).to_ascii_lowercase().contains("autopatch"))
    {
        return Ok((
            FindingStatus::Pass,
            "Windows Autopatch update rings assigned".to_string(),
        ));
    }
    if assigned.is_empty() {
        return Ok((
            FindingStatus::Fail,
            format!(
                "{} update rings, none assigned (and no Autopatch rings)",
                rings.len()
            ),
        ));
    }
    let i = |r: &Value, k: &str| r.get(k).and_then(|v| v.as_i64());
    let good: Vec<&str> = assigned
        .iter()
        .filter(|r| {
            let quality = i(r, "qualityUpdatesDeferralPeriodInDays").unwrap_or(i64::MAX) <= 7;
            let feature = i(r, "featureUpdatesDeferralPeriodInDays").unwrap_or(i64::MAX) <= 30;
            let deadline = i(r, "deadlineForQualityUpdatesInDays").is_some_and(|d| d > 0);
            let paused = r
                .get("qualityUpdatesPaused")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            quality && feature && deadline && !paused
        })
        .map(|r| name_of(r))
        .collect();
    Ok(if good.is_empty() {
        (
            FindingStatus::Warning,
            format!(
                "{} assigned rings, none with quality deferral <= 7 days, feature deferral <= 30 days and a quality deadline",
                assigned.len()
            ),
        )
    } else {
        (
            FindingStatus::Pass,
            format!("Compliant rings: {}", good.join(", ")),
        )
    })
}

/// Every `settingDefinitionId` / `value` pair in a settings-catalog policy's settings, flattened. Group
/// and choice children are nested; the walk keeps the parent's definition id for context.
fn walk_settings(v: &Value, parent: &str, own: &str, out: &mut Vec<(String, String, String)>) {
    match v {
        Value::Array(a) => {
            for x in a {
                walk_settings(x, parent, own, out);
            }
        }
        Value::Object(o) => {
            // An explicit definition id starts a new level; `choiceSettingValue` and friends inherit it.
            let (parent, own) = match o.get("settingDefinitionId").and_then(|d| d.as_str()) {
                Some(d) => (own.to_string(), d.to_ascii_lowercase()),
                None => (parent.to_string(), own.to_string()),
            };
            if let Some(val) = o.get("value").and_then(|x| x.as_str()) {
                out.push((parent.clone(), own.clone(), val.to_ascii_lowercase()));
            }
            for (k, child) in o {
                if k == "value" {
                    continue;
                }
                walk_settings(child, &parent, &own, out);
            }
        }
        _ => {}
    }
}

pub fn flatten_settings(settings: &[Value]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for s in settings {
        walk_settings(s, "", "", &mut out);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AsrMode {
    Off,
    Audit,
    Warn,
    Block,
}

impl AsrMode {
    fn parse(suffix: &str) -> Option<Self> {
        match suffix {
            "block" => Some(Self::Block),
            "warn" => Some(Self::Warn),
            "audit" => Some(Self::Audit),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Audit => "audit",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

const ASR_MARKER: &str = "attacksurfacereductionrules_";

/// ASR rule name -> strongest mode across the given settings.
pub fn asr_rules(settings: &[Value]) -> BTreeMap<String, AsrMode> {
    let mut rules: BTreeMap<String, AsrMode> = BTreeMap::new();
    for (_, def, val) in flatten_settings(settings) {
        let Some(pos) = def.find(ASR_MARKER) else {
            continue;
        };
        let rule = &def[pos + ASR_MARKER.len()..];
        if rule.is_empty() || rule.contains("perruleexclusions") || rule.contains("exclusions") {
            continue;
        }
        let Some(suffix) = val.rsplit('_').next() else {
            continue;
        };
        let Some(mode) = AsrMode::parse(suffix) else {
            continue;
        };
        let e = rules.entry(rule.to_string()).or_insert(mode);
        if mode > *e {
            *e = mode;
        }
    }
    rules
}

pub const ASR_REQUIRED: [(&str, &str); 4] = [
    (
        "blockallofficeapplicationsfromcreatingchildprocesses",
        "Office child processes",
    ),
    (
        "blockwin32apicallsfromofficemacros",
        "Win32 API from macros",
    ),
    (
        "blockexecutablecontentfromemailclientandwebmail",
        "Executable content from email",
    ),
    (
        "blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem",
        "LSASS credential stealing",
    ),
];

/// INTUNE-ASR-001 over the merged rules of the assigned ASR policies.
pub fn asr_001(rules: &BTreeMap<String, AsrMode>, assigned_policies: usize) -> Outcome {
    if rules.is_empty() {
        return Ok((
            FindingStatus::Fail,
            format!("No ASR rules configured ({assigned_policies} assigned ASR policies)"),
        ));
    }
    let mut blocked = Vec::new();
    let mut weak = Vec::new();
    let mut missing = Vec::new();
    for (rule, label) in ASR_REQUIRED {
        match rules.get(rule) {
            Some(AsrMode::Block) => blocked.push(label),
            Some(m) => weak.push(format!("{label}: {}", m.label())),
            None => missing.push(label),
        }
    }
    let total_block = rules.values().filter(|m| **m == AsrMode::Block).count();
    let summary = format!("{} rules configured, {total_block} in block", rules.len());
    Ok(if weak.is_empty() && missing.is_empty() {
        (
            FindingStatus::Pass,
            format!("{summary}; required rules all block"),
        )
    } else {
        let mut parts = Vec::new();
        if !weak.is_empty() {
            parts.push(format!("not blocking: {}", weak.join(", ")));
        }
        if !missing.is_empty() {
            parts.push(format!("missing: {}", missing.join(", ")));
        }
        (
            FindingStatus::Warning,
            format!("{summary}; {}", parts.join("; ")),
        )
    })
}

pub const OFFICE_APPS: [&str; 8] = [
    "word",
    "excel",
    "powerpoint",
    "access",
    "visio",
    "outlook",
    "publisher",
    "project",
];
const MACRO_CORE_APPS: [&str; 3] = ["word", "excel", "powerpoint"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacroPosture {
    /// Apps with "Block macros from running in Office files from the Internet" enabled.
    pub block_internet: BTreeSet<String>,
    /// App -> VBA Macro Notification Settings value (1 enable all, 2 disable with notification,
    /// 3 disable except signed, 4 disable without notification).
    pub vba_mode: BTreeMap<String, u8>,
}

fn office_app(def: &str) -> Option<&'static str> {
    OFFICE_APPS
        .iter()
        .copied()
        .find(|app| def.contains(&format!("{app}16")) || def.contains(&format!("microsoft{app}")))
}

/// Office ADMX macro settings in a settings-catalog policy.
pub fn macro_settings(settings: &[Value]) -> MacroPosture {
    let mut posture = MacroPosture::default();
    let flat = flatten_settings(settings);
    for (parent, def, val) in &flat {
        if def.contains("blockmacroexecutionfrominternet")
            && !parent.contains("blockmacroexecutionfrominternet")
        {
            if let Some(app) = office_app(def) {
                if val.ends_with("_1") {
                    posture.block_internet.insert(app.to_string());
                }
            }
        }
        // The dropdown is a child choice under the vbawarningspolicy setting; its value ends in the enum.
        if def.contains("vbawarningspolicy") && parent.contains("vbawarningspolicy") {
            if let Some(app) = office_app(def) {
                if let Some(n) = val.rsplit('_').next().and_then(|n| n.parse::<u8>().ok()) {
                    if (1..=4).contains(&n) {
                        posture.vba_mode.insert(app.to_string(), n);
                    }
                }
            }
        }
    }
    // A vbawarningspolicy toggled off (`_0`) at the top level carries no dropdown; drop any stale mode.
    for (parent, def, val) in &flat {
        if def.contains("vbawarningspolicy")
            && !parent.contains("vbawarningspolicy")
            && val.ends_with("_0")
        {
            if let Some(app) = office_app(def) {
                posture.vba_mode.remove(app);
            }
        }
    }
    posture
}

impl MacroPosture {
    pub fn merge(&mut self, other: MacroPosture) {
        self.block_internet.extend(other.block_internet);
        for (app, mode) in other.vba_mode {
            let e = self.vba_mode.entry(app).or_insert(mode);
            if mode > *e {
                *e = mode;
            }
        }
    }
}

/// INTUNE-MACRO-001 over the merged posture of assigned policies.
pub fn macro_001(p: &MacroPosture) -> Outcome {
    if p.block_internet.is_empty() && p.vba_mode.is_empty() {
        return Ok((
            FindingStatus::Fail,
            "No Intune settings-catalog macro policy assigned (if macros are controlled by Cloud Policy or Group Policy, attest)".to_string(),
        ));
    }
    let mut gaps = Vec::new();
    for app in MACRO_CORE_APPS {
        if !p.block_internet.contains(app) {
            gaps.push(format!("{app}: internet macros not blocked"));
        }
        match p.vba_mode.get(app) {
            Some(4) => {}
            Some(3) => gaps.push(format!("{app}: signed macros still allowed")),
            Some(m) => gaps.push(format!("{app}: VBA notification setting {m}")),
            None => gaps.push(format!("{app}: VBA macros not disabled")),
        }
    }
    let summary = format!(
        "Internet macros blocked for {}; VBA disabled without notification for {}",
        p.block_internet
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        p.vba_mode
            .iter()
            .filter(|(_, m)| **m == 4)
            .map(|(a, _)| a.clone())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(if gaps.is_empty() {
        (FindingStatus::Pass, summary)
    } else {
        (
            FindingStatus::Warning,
            format!("{summary}; gaps: {}", gaps.join(", ")),
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppControlMode {
    Unknown,
    Audit,
    Enforce,
}

/// Mode of an App Control for Business policy from its settings. Built-in controls carry audit/enforce in
/// the choice value; an uploaded XML policy's mode is inside the XML, so it reports `Unknown`.
pub fn app_control_mode(settings: &[Value]) -> Option<AppControlMode> {
    let mut mode: Option<AppControlMode> = None;
    for (_, def, val) in flatten_settings(settings) {
        if !def.contains("applicationcontrol") {
            continue;
        }
        let m = if val.contains("audit") {
            AppControlMode::Audit
        } else if val.contains("enforce") || val.contains("enabled") || val.ends_with("_1") {
            AppControlMode::Enforce
        } else if def.contains("_policies_") || def.contains("configurations") {
            AppControlMode::Unknown
        } else {
            continue;
        };
        mode = Some(mode.map_or(m, |cur| cur.max(m)));
    }
    mode
}

/// Legacy `windows10EndpointProtectionConfiguration.appLockerApplicationControl`.
pub fn legacy_app_control_mode(config: &Value) -> Option<AppControlMode> {
    let v = config
        .get("appLockerApplicationControl")?
        .as_str()?
        .to_ascii_lowercase();
    if v.starts_with("enforce") {
        Some(AppControlMode::Enforce)
    } else if v.starts_with("audit") {
        Some(AppControlMode::Audit)
    } else {
        None
    }
}

/// INTUNE-WDAC-001 over the modes of assigned App Control / AppLocker policies.
pub fn wdac_001(modes: &[AppControlMode]) -> Outcome {
    if modes.is_empty() {
        return Ok((
            FindingStatus::Fail,
            "No App Control for Business or AppLocker policy assigned".to_string(),
        ));
    }
    let enforce = modes
        .iter()
        .filter(|m| **m == AppControlMode::Enforce)
        .count();
    let audit = modes
        .iter()
        .filter(|m| **m == AppControlMode::Audit)
        .count();
    let unknown = modes.len() - enforce - audit;
    let summary = format!(
        "{} policies: {enforce} enforce, {audit} audit, {unknown} mode not readable",
        modes.len()
    );
    Ok(if enforce > 0 {
        (FindingStatus::Pass, summary)
    } else {
        (
            FindingStatus::Warning,
            format!("{summary}; no policy in enforce mode"),
        )
    })
}

fn template_family(p: &Value) -> &str {
    p.get("templateReference")
        .and_then(|t| t.get("templateFamily"))
        .and_then(|f| f.as_str())
        .unwrap_or("none")
}

fn catalog_platform(p: &Value) -> Option<Platform> {
    p.get("platforms")
        .and_then(|s| s.as_str())
        .and_then(Platform::parse)
}

/// INTUNE-ENCRYPTION-001: BitLocker (Windows) and FileVault (macOS, when macOS devices exist) policies assigned.
pub fn encryption_001(
    config_policies: &[Value],
    device_configs: &[Value],
    devices: &[Value],
) -> Outcome {
    let mut covered: BTreeSet<Platform> = BTreeSet::new();
    for p in config_policies.iter().filter(|p| is_assigned(p)) {
        if template_family(p).eq_ignore_ascii_case("endpointSecurityDiskEncryption") {
            if let Some(plat) = catalog_platform(p) {
                covered.insert(plat);
            }
        }
    }
    for c in device_configs.iter().filter(|c| is_assigned(c)) {
        let t = odata_type(c);
        if t.ends_with("windows10EndpointProtectionConfiguration")
            && c.get("bitLockerEncryptDevice")
                .and_then(|b| b.as_bool())
                .unwrap_or(false)
        {
            covered.insert(Platform::Windows);
        }
        if t.ends_with("macOSEndpointProtectionConfiguration")
            && c.get("fileVaultEnabled")
                .and_then(|b| b.as_bool())
                .unwrap_or(false)
        {
            covered.insert(Platform::MacOs);
        }
    }
    let in_use = platforms_in_use(devices);
    let mut needed = vec![Platform::Windows];
    if in_use.contains_key(&Platform::MacOs) {
        needed.push(Platform::MacOs);
    }
    let missing: Vec<&str> = needed
        .iter()
        .filter(|p| !covered.contains(p))
        .map(|p| p.label())
        .collect();
    let covered_text = covered
        .iter()
        .map(|p| p.label())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(if covered.is_empty() {
        (
            FindingStatus::Fail,
            "No disk encryption policy assigned".to_string(),
        )
    } else if missing.is_empty() {
        (
            FindingStatus::Pass,
            format!("Encryption enforced for {covered_text}"),
        )
    } else {
        (
            FindingStatus::Warning,
            format!(
                "Encryption enforced for {covered_text}; missing: {}",
                missing.join(", ")
            ),
        )
    })
}

/// INTUNE-SECURITY-001: an antivirus policy or security baseline plus an ASR policy are assigned.
pub fn security_001(config_policies: &[Value]) -> Outcome {
    let assigned: Vec<&Value> = config_policies.iter().filter(|p| is_assigned(p)).collect();
    let count = |family: &str| {
        assigned
            .iter()
            .filter(|p| template_family(p).eq_ignore_ascii_case(family))
            .count()
    };
    let baseline = count("baseline");
    let av = count("endpointSecurityAntivirus");
    let asr = count("endpointSecurityAttackSurfaceReduction");
    let summary = format!(
        "{baseline} security baselines, {av} antivirus policies, {asr} ASR policies assigned"
    );
    Ok(if (baseline > 0 || av > 0) && asr > 0 {
        (FindingStatus::Pass, summary)
    } else if baseline + av + asr == 0 {
        (FindingStatus::Fail, summary)
    } else {
        (
            FindingStatus::Warning,
            format!("{summary}; need antivirus (or a baseline) and ASR"),
        )
    })
}

/// INTUNE-RBAC-001: role assignments scoped only by the default scope tag.
pub fn rbac_001(assignments: &[Value]) -> Outcome {
    if assignments.is_empty() {
        return Ok((
            FindingStatus::Info,
            "No Intune role assignments".to_string(),
        ));
    }
    let unscoped: Vec<&str> = assignments
        .iter()
        .filter(|a| {
            a.get("roleScopeTagIds")
                .and_then(|t| t.as_array())
                .is_none_or(|t| t.is_empty() || t.iter().all(|x| x.as_str() == Some("0")))
        })
        .map(name_of)
        .collect();
    Ok(if unscoped.is_empty() {
        (
            FindingStatus::Pass,
            format!(
                "All {} role assignments use custom scope tags",
                assignments.len()
            ),
        )
    } else {
        (
            FindingStatus::Warning,
            format!(
                "{} of {} role assignments use only the default scope tag: {}",
                unscoped.len(),
                assignments.len(),
                unscoped.join(", ")
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn assigned() -> Value {
        json!([{"id": "a1", "target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}])
    }

    #[test]
    fn compliance_per_platform() {
        let devices = vec![
            json!({"operatingSystem": "Windows"}),
            json!({"operatingSystem": "iOS"}),
            json!({"operatingSystem": "Linux (ubuntu)"}),
        ];
        let classic = vec![
            json!({"@odata.type": "#microsoft.graph.windows10CompliancePolicy", "assignments": assigned()}),
            json!({"@odata.type": "#microsoft.graph.iosCompliancePolicy", "assignments": []}),
        ];
        let (s, text) = compliance_001(&classic, &[], &devices).unwrap();
        assert_eq!(s, FindingStatus::Warning);
        assert!(
            text.contains("iOS/iPadOS") && text.contains("Linux"),
            "{text}"
        );

        let catalog = vec![json!({"platforms": "linux", "assignments": assigned()})];
        let classic2 = vec![
            classic[0].clone(),
            json!({"@odata.type": "#microsoft.graph.iosCompliancePolicy", "assignments": assigned()}),
        ];
        assert_eq!(
            compliance_001(&classic2, &catalog, &devices).unwrap().0,
            FindingStatus::Pass
        );
        assert_eq!(
            compliance_001(
                &[json!({"@odata.type": "#microsoft.graph.windows10CompliancePolicy"})],
                &[],
                &devices
            )
            .unwrap()
            .0,
            FindingStatus::Fail
        );
        assert_eq!(
            compliance_002(&json!({"secureByDefault": false}))
                .unwrap()
                .0,
            FindingStatus::Fail
        );
        assert!(compliance_002(&json!({})).is_err());
    }

    #[test]
    fn enrolment_restrictions() {
        let cfg = |personal_ios: bool| {
            vec![json!({
                "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
                "priority": 0,
                "windowsRestriction": {"platformBlocked": false, "personalDeviceEnrollmentBlocked": true},
                "iosRestriction": {"platformBlocked": false, "personalDeviceEnrollmentBlocked": personal_ios},
                "androidRestriction": {"platformBlocked": true, "personalDeviceEnrollmentBlocked": false},
                "androidForWorkRestriction": {"platformBlocked": false, "personalDeviceEnrollmentBlocked": true},
                "macOSRestriction": {"platformBlocked": false, "personalDeviceEnrollmentBlocked": true}
            })]
        };
        assert_eq!(enroll_001(&cfg(true)).unwrap().0, FindingStatus::Pass);
        let (s, text) = enroll_001(&cfg(false)).unwrap();
        assert_eq!(s, FindingStatus::Warning);
        assert!(text.contains("iOS"), "{text}");
        assert!(enroll_001(&[
            json!({"@odata.type": "#microsoft.graph.deviceEnrollmentLimitConfiguration"})
        ])
        .is_err());
    }

    #[test]
    fn multi_admin_approval_coverage() {
        let p = |ty: &str, approvers: Vec<&str>| json!({"policyType": ty, "approverGroupIds": approvers});
        assert_eq!(multiapproval_001(&[]).unwrap().0, FindingStatus::Fail);
        let (s, text) = multiapproval_001(&[p("app", vec!["g"]), p("deviceWipe", vec![])]).unwrap();
        assert_eq!(s, FindingStatus::Warning);
        assert!(
            text.contains("deviceWipe") && text.contains("no approver group"),
            "{text}"
        );
        let full = [
            p("deviceAction", vec!["g"]),
            p("script", vec!["g"]),
            p("app", vec!["g"]),
        ];
        assert_eq!(multiapproval_001(&full).unwrap().0, FindingStatus::Pass);
    }

    #[test]
    fn update_rings() {
        let ring = |q: i64, f: i64, deadline: Option<i64>, name: &str| {
            json!({
                "@odata.type": "#microsoft.graph.windowsUpdateForBusinessConfiguration",
                "displayName": name,
                "qualityUpdatesDeferralPeriodInDays": q,
                "featureUpdatesDeferralPeriodInDays": f,
                "deadlineForQualityUpdatesInDays": deadline,
                "assignments": assigned()
            })
        };
        assert_eq!(update_001(&[]).unwrap().0, FindingStatus::Fail);
        assert_eq!(
            update_001(&[ring(14, 60, None, "Slow")]).unwrap().0,
            FindingStatus::Warning
        );
        assert_eq!(
            update_001(&[ring(14, 60, None, "Slow"), ring(3, 14, Some(5), "Fast")])
                .unwrap()
                .0,
            FindingStatus::Pass
        );
        assert_eq!(
            update_001(&[ring(30, 180, None, "Windows Autopatch - Broad")])
                .unwrap()
                .0,
            FindingStatus::Pass
        );
    }

    fn asr_setting(rule: &str, mode: &str) -> Value {
        let base =
            format!("device_vendor_msft_policy_config_defender_attacksurfacereductionrules_{rule}");
        json!({
            "settingInstance": {
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules",
                "groupSettingCollectionValue": [{
                    "children": [{
                        "settingDefinitionId": base,
                        "choiceSettingValue": {"value": format!("{base}_{mode}"), "children": [
                            {"settingDefinitionId": format!("{base}_perruleexclusions"), "simpleSettingCollectionValue": [{"value": "c:\\tmp"}]}
                        ]}
                    }]
                }]
            }
        })
    }

    #[test]
    fn asr_rules_and_modes() {
        let settings = vec![
            asr_setting(
                "blockallofficeapplicationsfromcreatingchildprocesses",
                "block",
            ),
            asr_setting("blockwin32apicallsfromofficemacros", "audit"),
            asr_setting("blockexecutablecontentfromemailclientandwebmail", "block"),
        ];
        let rules = asr_rules(&settings);
        assert_eq!(rules.len(), 3, "{rules:?}");
        assert_eq!(rules["blockwin32apicallsfromofficemacros"], AsrMode::Audit);
        let (s, text) = asr_001(&rules, 1).unwrap();
        assert_eq!(s, FindingStatus::Warning);
        assert!(
            text.contains("Win32 API from macros: audit") && text.contains("missing: LSASS"),
            "{text}"
        );

        let mut all = settings.clone();
        all.push(asr_setting("blockwin32apicallsfromofficemacros", "block"));
        all.push(asr_setting(
            "blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem",
            "block",
        ));
        assert_eq!(asr_001(&asr_rules(&all), 2).unwrap().0, FindingStatus::Pass);
        assert_eq!(asr_001(&BTreeMap::new(), 0).unwrap().0, FindingStatus::Fail);
    }

    fn macro_setting(app: &str, block_internet: bool, vba: Option<u8>) -> Value {
        let prefix = format!("user_vendor_msft_policy_config_{app}16v2~policy~l_microsoftoffice{app}~l_{app}options~l_security~l_trustcenter");
        let block_id = format!("{prefix}_l_blockmacroexecutionfrominternet");
        let vba_id = format!("{prefix}_l_vbawarningspolicy");
        let vba_child = match vba {
            Some(n) => {
                json!([{"settingDefinitionId": format!("{vba_id}_l_empty"), "choiceSettingValue": {"value": format!("{vba_id}_l_empty_{n}"), "children": []}}])
            }
            None => json!([]),
        };
        json!([
            {"settingInstance": {"settingDefinitionId": block_id, "choiceSettingValue": {"value": format!("{block_id}_{}", if block_internet {1} else {0}), "children": []}}},
            {"settingInstance": {"settingDefinitionId": vba_id, "choiceSettingValue": {"value": format!("{vba_id}_{}", if vba.is_some() {1} else {0}), "children": vba_child}}}
        ])
    }

    #[test]
    fn macro_posture() {
        let mut settings = Vec::new();
        settings.extend(
            macro_setting("word", true, Some(4))
                .as_array()
                .unwrap()
                .clone(),
        );
        settings.extend(
            macro_setting("excel", true, Some(3))
                .as_array()
                .unwrap()
                .clone(),
        );
        settings.extend(
            macro_setting("powerpoint", false, None)
                .as_array()
                .unwrap()
                .clone(),
        );
        let p = macro_settings(&settings);
        assert_eq!(
            p.block_internet.iter().cloned().collect::<Vec<_>>(),
            vec!["excel", "word"]
        );
        assert_eq!(p.vba_mode.get("word"), Some(&4));
        assert_eq!(p.vba_mode.get("excel"), Some(&3));
        assert_eq!(p.vba_mode.get("powerpoint"), None);
        let (s, text) = macro_001(&p).unwrap();
        assert_eq!(s, FindingStatus::Warning);
        assert!(
            text.contains("excel: signed macros still allowed")
                && text.contains("powerpoint: internet macros not blocked"),
            "{text}"
        );

        let mut good = Vec::new();
        for app in ["word", "excel", "powerpoint"] {
            good.extend(
                macro_setting(app, true, Some(4))
                    .as_array()
                    .unwrap()
                    .clone(),
            );
        }
        assert_eq!(
            macro_001(&macro_settings(&good)).unwrap().0,
            FindingStatus::Pass
        );
        assert_eq!(
            macro_001(&MacroPosture::default()).unwrap().0,
            FindingStatus::Fail
        );
    }

    #[test]
    fn app_control_modes() {
        let audit = vec![
            json!({"settingInstance": {"settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_builtincontrols_enableappcontrol", "choiceSettingValue": {"value": "device_vendor_msft_policy_config_applicationcontrol_builtincontrols_enableappcontrol_audit"}}}),
        ];
        assert_eq!(app_control_mode(&audit), Some(AppControlMode::Audit));
        let enforce = vec![
            json!({"settingInstance": {"settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_builtincontrols_enableappcontrol", "choiceSettingValue": {"value": "device_vendor_msft_policy_config_applicationcontrol_builtincontrols_enableappcontrol_enforce"}}}),
        ];
        assert_eq!(app_control_mode(&enforce), Some(AppControlMode::Enforce));
        let xml = vec![
            json!({"settingInstance": {"settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_configurations_{abc}_policies_{def}_policy", "simpleSettingValue": {"value": "PD94bWw..."}}}),
        ];
        assert_eq!(app_control_mode(&xml), Some(AppControlMode::Unknown));
        assert_eq!(
            app_control_mode(&[
                json!({"settingInstance": {"settingDefinitionId": "device_vendor_msft_policy_config_defender_x", "choiceSettingValue": {"value": "y_1"}}})
            ]),
            None
        );
        assert_eq!(
            legacy_app_control_mode(
                &json!({"appLockerApplicationControl": "enforceComponentsStoreAppsAndSmartlocker"})
            ),
            Some(AppControlMode::Enforce)
        );

        assert_eq!(wdac_001(&[]).unwrap().0, FindingStatus::Fail);
        assert_eq!(
            wdac_001(&[AppControlMode::Audit, AppControlMode::Unknown])
                .unwrap()
                .0,
            FindingStatus::Warning
        );
        assert_eq!(
            wdac_001(&[AppControlMode::Audit, AppControlMode::Enforce])
                .unwrap()
                .0,
            FindingStatus::Pass
        );
    }

    #[test]
    fn encryption_and_baseline() {
        let devices = vec![
            json!({"operatingSystem": "Windows"}),
            json!({"operatingSystem": "macOS"}),
        ];
        let bitlocker = json!({"templateReference": {"templateFamily": "endpointSecurityDiskEncryption"}, "platforms": "windows10", "assignments": assigned()});
        let (s, text) = encryption_001(std::slice::from_ref(&bitlocker), &[], &devices).unwrap();
        assert_eq!(s, FindingStatus::Warning);
        assert!(text.contains("missing: macOS"), "{text}");
        let filevault = json!({"@odata.type": "#microsoft.graph.macOSEndpointProtectionConfiguration", "fileVaultEnabled": true, "assignments": assigned()});
        assert_eq!(
            encryption_001(std::slice::from_ref(&bitlocker), &[filevault], &devices)
                .unwrap()
                .0,
            FindingStatus::Pass
        );
        assert_eq!(
            encryption_001(&[], &[], &devices).unwrap().0,
            FindingStatus::Fail
        );
        assert_eq!(
            encryption_001(&[bitlocker], &[], &[json!({"operatingSystem": "Windows"})])
                .unwrap()
                .0,
            FindingStatus::Pass
        );

        let av = json!({"templateReference": {"templateFamily": "endpointSecurityAntivirus"}, "assignments": assigned()});
        let asr = json!({"templateReference": {"templateFamily": "endpointSecurityAttackSurfaceReduction"}, "assignments": assigned()});
        let unassigned_asr = json!({"templateReference": {"templateFamily": "endpointSecurityAttackSurfaceReduction"}, "assignments": []});
        assert_eq!(
            security_001(&[av.clone(), unassigned_asr]).unwrap().0,
            FindingStatus::Warning
        );
        assert_eq!(security_001(&[av, asr]).unwrap().0, FindingStatus::Pass);
        assert_eq!(security_001(&[]).unwrap().0, FindingStatus::Fail);
    }

    #[test]
    fn rbac_scope_tags() {
        assert_eq!(rbac_001(&[]).unwrap().0, FindingStatus::Info);
        let a = json!({"displayName": "Helpdesk", "roleScopeTagIds": ["0"]});
        let b = json!({"displayName": "Site A", "roleScopeTagIds": ["0", "3"]});
        assert_eq!(
            rbac_001(&[a.clone(), b.clone()]).unwrap().0,
            FindingStatus::Warning
        );
        assert_eq!(rbac_001(&[b]).unwrap().0, FindingStatus::Pass);
    }
}
