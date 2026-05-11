use super::{AssessmentModule, ModuleResult};
use crate::assessment::engine::TenantInfo;
use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;
use anyhow::Result;
use async_trait::async_trait;

pub struct IdentityModule;

// ---------------------------------------------------------------------------
// Break-glass / emergency-access account detection
// ---------------------------------------------------------------------------

fn is_break_glass(upn: &str, display_name: &str) -> bool {
    let lower_upn = upn.to_lowercase();
    let lower_dn = display_name.to_lowercase();
    let patterns = ["breakglass", "break.glass", "emergency.access", "bg.admin"];
    patterns
        .iter()
        .any(|p| lower_upn.contains(p) || lower_dn.contains(p))
}

#[async_trait]
impl AssessmentModule for IdentityModule {
    fn name(&self) -> &str {
        "Identity"
    }

    fn description(&self) -> &str {
        "Entra ID / identity and access management security assessment"
    }

    async fn run(
        &self,
        graph: &GraphClient,
        tenant: &TenantInfo,
        registry: &ControlRegistry,
    ) -> Result<ModuleResult> {
        let start = std::time::Instant::now();
        let mut findings: Vec<Finding> = Vec::new();

        // ===================================================================
        // ENTRA-ADMIN-001 : Global Administrator count
        // ===================================================================
        match check_global_admin_count(graph, registry).await {
            Ok(f) => findings.extend(f),
            Err(e) => {
                tracing::warn!("ENTRA-ADMIN-001 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-ADMIN-002 : Privileged role inventory
        // ===================================================================
        match check_privileged_role_inventory(graph, registry).await {
            Ok(f) => findings.extend(f),
            Err(e) => {
                tracing::warn!("ENTRA-ADMIN-002 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-ADMIN-003 : Dedicated admin accounts
        // ===================================================================
        match check_dedicated_admin_accounts(graph, registry).await {
            Ok(f) => findings.extend(f),
            Err(e) => {
                tracing::warn!("ENTRA-ADMIN-003 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-ADMIN-004 : Stale admin detection
        // ===================================================================
        match check_stale_admins(graph, registry).await {
            Ok(f) => findings.extend(f),
            Err(e) => {
                tracing::warn!("ENTRA-ADMIN-004 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-MFA-001 : MFA registration
        // ===================================================================
        match check_mfa_registration(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-MFA-001 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-CA-001..003 : Conditional Access
        // ===================================================================
        match check_conditional_access(graph, registry).await {
            Ok(f) => findings.extend(f),
            Err(e) => {
                tracing::warn!("ENTRA-CA checks failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-PASSWORD-001 : Authentication methods policy
        // ===================================================================
        match check_auth_methods_policy(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-PASSWORD-001 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-PASSWORD-002 : SSPR enabled
        // ===================================================================
        match check_sspr(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-PASSWORD-002 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-SECDEFAULT-001 : Security defaults
        // ===================================================================
        match check_security_defaults(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-SECDEFAULT-001 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-CONSENT-001 : User consent restricted
        // ===================================================================
        match check_user_consent(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-CONSENT-001 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-CONSENT-002 : Admin consent workflow
        // ===================================================================
        match check_admin_consent_workflow(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-CONSENT-002 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-ENTAPP-001..005 : Enterprise app checks
        // ===================================================================
        match check_enterprise_apps(graph, registry).await {
            Ok(f) => findings.extend(f),
            Err(e) => {
                tracing::warn!("ENTRA-ENTAPP checks failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-APPREG-001..003 : App registrations
        // ===================================================================
        match check_app_registrations(graph, registry).await {
            Ok(f) => findings.extend(f),
            Err(e) => {
                tracing::warn!("ENTRA-APPREG checks failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-PIM-001 : PIM enabled
        // ===================================================================
        match check_pim(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-PIM-001 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-GUEST-001..003 : Guest settings
        // ===================================================================
        match check_guest_settings(graph, registry).await {
            Ok(f) => findings.extend(f),
            Err(e) => {
                tracing::warn!("ENTRA-GUEST checks failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-DEVICE-001 : Device registration
        // ===================================================================
        match check_device_registration(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-DEVICE-001 failed: {e}");
            }
        }

        // ===================================================================
        // CA-LEGACYAUTH-001 : Legacy/basic auth blocking
        // ===================================================================
        match check_ca_legacy_auth_blocking(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("CA-LEGACYAUTH-001 failed: {e}");
            }
        }

        // ===================================================================
        // CA-MFA-ADMIN-001 : MFA required for admin roles
        // ===================================================================
        match check_ca_mfa_admin(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("CA-MFA-ADMIN-001 failed: {e}");
            }
        }

        // ===================================================================
        // CA-MFA-ALL-001 : MFA required for all users
        // ===================================================================
        match check_ca_mfa_all_users(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("CA-MFA-ALL-001 failed: {e}");
            }
        }

        // ===================================================================
        // CA-SIGNINRISK-001 : Sign-in risk policy
        // ===================================================================
        match check_ca_signin_risk(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("CA-SIGNINRISK-001 failed: {e}");
            }
        }

        // ===================================================================
        // CA-USERRISK-001 : User risk policy
        // ===================================================================
        match check_ca_user_risk(graph, tenant, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("CA-USERRISK-001 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-SSPR-001 : Self-service password reset
        // ===================================================================
        match check_sspr_enabled(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-SSPR-001 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-PERUSER-001 : Per-user MFA (legacy) check
        // ===================================================================
        match check_per_user_mfa(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-PERUSER-001 failed: {e}");
            }
        }

        // ===================================================================
        // ENTRA-LINKEDIN-001 : LinkedIn integration
        // ===================================================================
        match check_linkedin_integration(graph, registry).await {
            Ok(f) => findings.push(f),
            Err(e) => {
                tracing::warn!("ENTRA-LINKEDIN-001 failed: {e}");
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(ModuleResult {
            module_name: self.name().to_string(),
            findings,
            raw_data: serde_json::json!({}),
            error: None,
            duration_ms,
        })
    }
}

// ===========================================================================
// Individual check implementations
// ===========================================================================

async fn check_global_admin_count(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let roles: Vec<serde_json::Value> = graph.get_all("/v1.0/directoryRoles").await?;

    let ga_role = roles
        .iter()
        .find(|r| r["displayName"].as_str().unwrap_or_default() == "Global Administrator");

    if let Some(role) = ga_role {
        let role_id = role["id"].as_str().unwrap_or_default();
        let members: Vec<serde_json::Value> = graph
            .get_all(&format!("/v1.0/directoryRoles/{role_id}/members"))
            .await?;

        let total_count = members.len();
        let operational: Vec<&serde_json::Value> = members
            .iter()
            .filter(|m| {
                let upn = m["userPrincipalName"].as_str().unwrap_or_default();
                let dn = m["displayName"].as_str().unwrap_or_default();
                !is_break_glass(upn, dn)
            })
            .collect();
        let op_count = operational.len();
        let bg_count = total_count - op_count;

        let status = if (2..=4).contains(&op_count) {
            FindingStatus::Pass
        } else if op_count == 1 || (5..=8).contains(&op_count) {
            FindingStatus::Warning
        } else {
            FindingStatus::Fail
        };

        findings.push(
            Finding::new(
                "ENTRA-ADMIN-001",
                "Identity",
                "Global Admins",
                "Global Administrator Count",
                "Number of Global Administrator role members should be between 2 and 4",
            )
            .status(status)
            .severity(registry.get_severity("ENTRA-ADMIN-001"))
            .current_value(format!(
                "{op_count} operational, {bg_count} break-glass (total {total_count})"
            ))
            .expected_value("2-4 operational Global Admins")
            .remediation(
                "Review Global Administrator assignments. Maintain 2-4 operational admins \
                 plus break-glass accounts. Use less-privileged roles where possible.",
            )
            .build(),
        );
    } else {
        findings.push(
            Finding::new(
                "ENTRA-ADMIN-001",
                "Identity",
                "Global Admins",
                "Global Administrator Count",
                "Global Administrator role not found or not yet activated",
            )
            .status(FindingStatus::Warning)
            .severity(registry.get_severity("ENTRA-ADMIN-001"))
            .current_value("Role not found")
            .expected_value("2-4 operational Global Admins")
            .remediation("Ensure the Global Administrator role is activated in the tenant.")
            .build(),
        );
    }

    Ok(findings)
}

async fn check_privileged_role_inventory(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let roles: Vec<serde_json::Value> = graph.get_all("/v1.0/directoryRoles").await?;

    let mut role_details: Vec<String> = Vec::new();
    for role in &roles {
        let role_id = role["id"].as_str().unwrap_or_default();
        let role_name = role["displayName"].as_str().unwrap_or("Unknown");
        match graph
            .get_all::<serde_json::Value>(&format!("/v1.0/directoryRoles/{role_id}/members"))
            .await
        {
            Ok(members) => {
                role_details.push(format!("{role_name}: {} members", members.len()));
            }
            Err(e) => {
                tracing::warn!("Failed to get members for role {role_name}: {e}");
                role_details.push(format!("{role_name}: error reading members"));
            }
        }
    }

    findings.push(
        Finding::new(
            "ENTRA-ADMIN-002",
            "Identity",
            "Privileged Roles",
            "Privileged Role Inventory",
            "Inventory of all activated directory roles and their member counts",
        )
        .status(FindingStatus::Info)
        .severity(registry.get_severity("ENTRA-ADMIN-002"))
        .current_value(format!("{} roles activated", roles.len()))
        .expected_value("Review role assignments for least-privilege")
        .remediation("Regularly review privileged role assignments and remove unnecessary access.")
        .details(serde_json::json!({ "roles": role_details }))
        .build(),
    );

    Ok(findings)
}

async fn check_dedicated_admin_accounts(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let roles: Vec<serde_json::Value> = graph.get_all("/v1.0/directoryRoles").await?;

    let privileged_roles = [
        "Global Administrator",
        "Privileged Role Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Security Administrator",
        "User Administrator",
    ];

    // Collect unique admin UPNs across all privileged roles
    let mut seen_upns = std::collections::HashSet::new();
    let mut admin_accounts: Vec<(String, Vec<String>)> = Vec::new(); // (upn, roles)

    for role in &roles {
        let role_name = role["displayName"].as_str().unwrap_or_default();
        if !privileged_roles.contains(&role_name) {
            continue;
        }
        let role_id = role["id"].as_str().unwrap_or_default();
        if let Ok(members) = graph
            .get_all::<serde_json::Value>(&format!("/v1.0/directoryRoles/{role_id}/members"))
            .await
        {
            for m in &members {
                let upn = m["userPrincipalName"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                if is_break_glass(&upn, m["displayName"].as_str().unwrap_or_default()) {
                    continue;
                }
                if seen_upns.insert(upn.clone()) {
                    admin_accounts.push((upn, vec![role_name.to_string()]));
                } else if let Some(entry) = admin_accounts.iter_mut().find(|(u, _)| *u == upn) {
                    entry.1.push(role_name.to_string());
                }
            }
        }
    }

    let total_admins = admin_accounts.len();

    // For small tenants (1-2 admins), a single person wearing multiple hats
    // is normal. The check should flag multi-role sprawl, not naming conventions.
    // For larger admin populations, check if admins hold excessive role combinations
    // that suggest they're using daily-driver accounts for admin work.

    let mut multi_role_admins: Vec<String> = Vec::new();
    let mut admin_summary: Vec<String> = Vec::new();

    for (upn, roles) in &admin_accounts {
        admin_summary.push(format!("{} ({})", upn, roles.join(", ")));
        // Flag admins with 3+ privileged roles as likely not dedicated
        if roles.len() >= 3 {
            multi_role_admins.push(format!("{} ({} roles)", upn, roles.len()));
        }
    }

    let (status, current_value, remediation_text) = if total_admins == 0 {
        (
            FindingStatus::Info,
            "No privileged admin accounts found".to_string(),
            "Ensure at least 2 Global Administrators are assigned.".to_string(),
        )
    } else if total_admins <= 2 {
        // Small tenant - informational; 1-2 admins is typical for small orgs
        (
            FindingStatus::Pass,
            format!(
                "{} admin account(s): {}",
                total_admins,
                admin_summary.join("; ")
            ),
            "For small tenants, ensure admin accounts use strong MFA and are not shared."
                .to_string(),
        )
    } else if multi_role_admins.is_empty() {
        (
            FindingStatus::Pass,
            format!(
                "{} admin accounts with appropriate role separation",
                total_admins
            ),
            "Admin role assignments look appropriate.".to_string(),
        )
    } else {
        (
            FindingStatus::Review,
            format!(
                "{} admin(s) hold 3+ privileged roles: {}. \
                 Consider whether these are dedicated admin accounts or daily-use accounts.",
                multi_role_admins.len(),
                multi_role_admins.join("; ")
            ),
            "Consider creating dedicated admin accounts separate from daily-use accounts. \
             Accounts with many privileged roles should be purpose-built admin identities \
             with strong MFA, not accounts also used for email and collaboration."
                .to_string(),
        )
    };

    findings.push(
        Finding::new(
            "ENTRA-ADMIN-003",
            "Identity",
            "Admin Accounts",
            "Dedicated Admin Accounts",
            "Evaluate whether privileged accounts are appropriately separated from daily-use accounts",
        )
        .status(status)
        .severity(registry.get_severity("ENTRA-ADMIN-003"))
        .current_value(current_value)
        .expected_value("Admin accounts should be dedicated or have appropriate role separation")
        .remediation(remediation_text)
        .affected_resources(admin_summary)
        .build(),
    );

    Ok(findings)
}

async fn check_stale_admins(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // First get the Global Administrator members
    let roles: Vec<serde_json::Value> = graph.get_all("/v1.0/directoryRoles").await?;
    let ga_role = roles
        .iter()
        .find(|r| r["displayName"].as_str().unwrap_or_default() == "Global Administrator");

    let admin_upns: Vec<String> = if let Some(role) = ga_role {
        let role_id = role["id"].as_str().unwrap_or_default();
        let members: Vec<serde_json::Value> = graph
            .get_all(&format!("/v1.0/directoryRoles/{role_id}/members"))
            .await?;
        members
            .iter()
            .filter_map(|m| m["userPrincipalName"].as_str().map(String::from))
            .collect()
    } else {
        Vec::new()
    };

    // Get users with sign-in activity (requires eventual consistency)
    let users: Vec<serde_json::Value> = graph
        .get_all_eventual(
            "/v1.0/users?$select=id,displayName,userPrincipalName,signInActivity&$top=999",
        )
        .await?;

    let now = chrono::Utc::now();
    let threshold = chrono::Duration::days(90);
    let mut stale_admins: Vec<String> = Vec::new();

    for user in &users {
        let upn = user["userPrincipalName"].as_str().unwrap_or_default();
        if !admin_upns.iter().any(|a| a.eq_ignore_ascii_case(upn)) {
            continue;
        }
        if is_break_glass(upn, user["displayName"].as_str().unwrap_or_default()) {
            continue;
        }
        if let Some(last_sign_in) = user["signInActivity"]["lastSignInDateTime"].as_str() {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(last_sign_in) {
                let age = now.signed_duration_since(dt.with_timezone(&chrono::Utc));
                if age > threshold {
                    stale_admins.push(format!("{upn} (last sign-in: {last_sign_in})"));
                }
            }
        } else {
            // No sign-in activity recorded at all
            stale_admins.push(format!("{upn} (no sign-in activity recorded)"));
        }
    }

    let status = if stale_admins.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };

    findings.push(
        Finding::new(
            "ENTRA-ADMIN-004",
            "Identity",
            "Admin Accounts",
            "Stale Admin Detection",
            "Admin accounts inactive for more than 90 days should be reviewed",
        )
        .status(status)
        .severity(registry.get_severity("ENTRA-ADMIN-004"))
        .current_value(format!("{} stale admin(s) detected", stale_admins.len()))
        .expected_value("No admin accounts inactive >90 days")
        .remediation(
            "Review and disable or remove admin accounts that have not signed in \
             for more than 90 days.",
        )
        .affected_resources(stale_admins)
        .build(),
    );

    Ok(findings)
}

async fn check_mfa_registration(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let details: Vec<serde_json::Value> = graph
        .get_all("/v1.0/reports/authenticationMethods/userRegistrationDetails")
        .await?;

    let total = details.len();
    let mfa_registered = details
        .iter()
        .filter(|d| d["isMfaRegistered"].as_bool().unwrap_or(false))
        .count();

    let pct = if total > 0 {
        (mfa_registered as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let pass_threshold = if total <= 5 { 80.0 } else { 90.0 };
    let status = if pct >= pass_threshold {
        FindingStatus::Pass
    } else if pct >= 70.0 {
        FindingStatus::Warning
    } else {
        FindingStatus::Fail
    };

    Ok(Finding::new(
        "ENTRA-MFA-001",
        "Identity",
        "Multi-Factor Authentication",
        "MFA Registration",
        "All users should be registered for MFA",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-MFA-001"))
    .current_value(format!(
        "{mfa_registered}/{total} users MFA-registered ({pct:.1}%)"
    ))
    .expected_value(format!(
        ">={pass_threshold:.0}% MFA registration (threshold for {} users)",
        if total <= 5 { "<=5" } else { ">5" }
    ))
    .remediation(
        "Enable and enforce MFA registration for all users via Conditional Access \
         or Security Defaults.",
    )
    .build())
}

async fn check_conditional_access(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let policies: Vec<serde_json::Value> = graph
        .get_all("/v1.0/identity/conditionalAccess/policies")
        .await?;

    let enabled_policies: Vec<&serde_json::Value> = policies
        .iter()
        .filter(|p| {
            let state = p["state"].as_str().unwrap_or_default();
            state == "enabled" || state == "enabledForReportingButNotEnforced"
        })
        .collect();
    let enabled_count = enabled_policies.len();

    // -----------------------------------------------------------------------
    // ENTRA-CA-001: Enabled policy count
    // -----------------------------------------------------------------------
    // Check if any enabled policy enforces MFA
    let has_mfa_coverage = enabled_policies.iter().any(|p| {
        let grant = p["grantControls"]["builtInControls"].as_array();
        grant
            .map(|arr| arr.iter().any(|g| g.as_str() == Some("mfa")))
            .unwrap_or(false)
    });

    let status_001 = if enabled_count == 0 {
        FindingStatus::Fail
    } else if has_mfa_coverage {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    };

    findings.push(
        Finding::new(
            "ENTRA-CA-001",
            "Identity",
            "Conditional Access",
            "Enabled Conditional Access Policies",
            "At least one Conditional Access policy should be enabled with MFA coverage",
        )
        .status(status_001)
        .severity(registry.get_severity("ENTRA-CA-001"))
        .current_value(format!(
            "{enabled_count} enabled policies; MFA coverage: {}",
            if has_mfa_coverage { "yes" } else { "no" }
        ))
        .expected_value(">=1 enabled Conditional Access policy with MFA enforcement")
        .remediation(
            "Create Conditional Access policies covering MFA enforcement, \
             device compliance, and location-based access.",
        )
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-CA-002: Coverage of "All users"
    // -----------------------------------------------------------------------
    let covers_all_users = enabled_policies.iter().any(|p| {
        if let Some(users) = p["conditions"]["users"]["includeUsers"].as_array() {
            users.iter().any(|u| {
                u.as_str()
                    .map(|s| s.eq_ignore_ascii_case("All"))
                    .unwrap_or(false)
            })
        } else {
            false
        }
    });

    findings.push(
        Finding::new(
            "ENTRA-CA-002",
            "Identity",
            "Conditional Access",
            "All Users Coverage",
            "At least one CA policy should target All Users",
        )
        .status(if covers_all_users {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .severity(registry.get_severity("ENTRA-CA-002"))
        .current_value(if covers_all_users {
            "At least one policy targets All Users".to_string()
        } else {
            "No policy targets All Users".to_string()
        })
        .expected_value("At least one policy targeting All Users")
        .remediation(
            "Ensure at least one Conditional Access policy targets All Users \
             with appropriate grant controls.",
        )
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-CA-003: Exclusion analysis
    // -----------------------------------------------------------------------
    let mut policies_with_exclusions = 0usize;
    let mut large_exclusion_policies: Vec<String> = Vec::new();

    for p in &enabled_policies {
        let name = p["displayName"].as_str().unwrap_or("Unnamed");
        let mut exclusion_count = 0usize;
        if let Some(arr) = p["conditions"]["users"]["excludeUsers"].as_array() {
            exclusion_count += arr.len();
        }
        if let Some(arr) = p["conditions"]["users"]["excludeGroups"].as_array() {
            exclusion_count += arr.len();
        }
        if let Some(arr) = p["conditions"]["users"]["excludeRoles"].as_array() {
            exclusion_count += arr.len();
        }
        if exclusion_count > 0 {
            policies_with_exclusions += 1;
        }
        if exclusion_count > 5 {
            large_exclusion_policies.push(format!("{name} ({exclusion_count} exclusions)"));
        }
    }

    let status_003 = if large_exclusion_policies.is_empty() {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    };

    findings.push(
        Finding::new(
            "ENTRA-CA-003",
            "Identity",
            "Conditional Access",
            "CA Exclusion Analysis",
            "Conditional Access policies should minimize exclusions",
        )
        .status(status_003)
        .severity(registry.get_severity("ENTRA-CA-003"))
        .current_value(format!(
            "{policies_with_exclusions} policies with exclusions, {} with >5 exclusions",
            large_exclusion_policies.len()
        ))
        .expected_value("No policies with excessive exclusions (>5)")
        .remediation(
            "Review CA policy exclusions. Use groups for exclusions rather than \
             individual users, and keep exclusions to a minimum.",
        )
        .affected_resources(large_exclusion_policies)
        .build(),
    );

    Ok(findings)
}

async fn check_auth_methods_policy(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policy: serde_json::Value = graph
        .get_json("/v1.0/policies/authenticationMethodsPolicy")
        .await?;

    let configs = policy["authenticationMethodConfigurations"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut enabled_methods: Vec<String> = Vec::new();
    let mut has_passwordless = false;

    for cfg in &configs {
        let id = cfg["id"].as_str().unwrap_or_default();
        let state = cfg["state"].as_str().unwrap_or_default();
        if state == "enabled" {
            enabled_methods.push(id.to_string());
            if matches!(
                id,
                "Fido2" | "MicrosoftAuthenticator" | "WindowsHelloForBusiness"
            ) {
                has_passwordless = true;
            }
        }
    }

    let status = if has_passwordless {
        FindingStatus::Pass
    } else {
        FindingStatus::Warning
    };

    Ok(Finding::new(
        "ENTRA-PASSWORD-001",
        "Identity",
        "Authentication Methods",
        "Authentication Methods Policy",
        "At least one passwordless authentication method should be enabled",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-PASSWORD-001"))
    .current_value(format!(
        "Enabled methods: {}; passwordless: {}",
        enabled_methods.join(", "),
        if has_passwordless { "yes" } else { "no" }
    ))
    .expected_value("At least one passwordless method (FIDO2, Authenticator, WHfB) enabled")
    .remediation(
        "Enable passwordless authentication methods such as FIDO2 security keys \
         or Microsoft Authenticator in the authentication methods policy.",
    )
    .build())
}

async fn check_sspr(graph: &GraphClient, registry: &ControlRegistry) -> Result<Finding> {
    let auth_policy: serde_json::Value =
        graph.get_json("/v1.0/policies/authorizationPolicy").await?;

    // The authorizationPolicy is returned with a value array for v1.0
    let policy = if let Some(arr) = auth_policy["value"].as_array() {
        arr.first().cloned().unwrap_or(auth_policy.clone())
    } else {
        auth_policy
    };

    let sspr = policy["allowedToUseSSPR"].as_bool();

    let (status, current) = match sspr {
        Some(true) => (FindingStatus::Pass, "SSPR is enabled"),
        Some(false) => (FindingStatus::Fail, "SSPR is disabled"),
        None => (FindingStatus::Review, "SSPR status could not be determined"),
    };

    Ok(Finding::new(
        "ENTRA-PASSWORD-002",
        "Identity",
        "Password Management",
        "Self-Service Password Reset",
        "Self-Service Password Reset should be enabled for all users",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-PASSWORD-002"))
    .current_value(current)
    .expected_value("SSPR enabled")
    .remediation(
        "Enable Self-Service Password Reset for all users in Entra ID > \
         Password Reset settings.",
    )
    .build())
}

async fn check_security_defaults(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policy: serde_json::Value = graph
        .get_json("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy")
        .await?;

    let is_enabled = policy["isEnabled"].as_bool().unwrap_or(false);

    // Security defaults are good for tenants without CA policies.
    // If CA policies are in use, security defaults should typically be off.
    let status = FindingStatus::Info;

    Ok(Finding::new(
        "ENTRA-SECDEFAULT-001",
        "Identity",
        "Security Defaults",
        "Security Defaults Status",
        "Security defaults provide baseline protection; \
         disable if Conditional Access policies are in use",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-SECDEFAULT-001"))
    .current_value(if is_enabled {
        "Security Defaults ENABLED"
    } else {
        "Security Defaults DISABLED"
    })
    .expected_value("Enabled (if no CA) or Disabled (if CA policies in use)")
    .remediation(
        "If using Conditional Access, disable Security Defaults. \
         If not using CA, enable Security Defaults for baseline protection.",
    )
    .build())
}

async fn check_user_consent(graph: &GraphClient, registry: &ControlRegistry) -> Result<Finding> {
    let auth_policy: serde_json::Value =
        graph.get_json("/v1.0/policies/authorizationPolicy").await?;

    let policy = if let Some(arr) = auth_policy["value"].as_array() {
        arr.first().cloned().unwrap_or(auth_policy.clone())
    } else {
        auth_policy
    };

    let consent_policies = policy["permissionGrantPoliciesAssigned"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let consent_strs: Vec<&str> = consent_policies.iter().filter_map(|v| v.as_str()).collect();

    // "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" means users
    // can consent to any app. If this is absent or restricted, it's better.
    let allows_user_consent = consent_strs.iter().any(|s| {
        s.contains("microsoft-user-default-legacy") || s.contains("microsoft-user-default-low")
    });

    let status = if allows_user_consent {
        FindingStatus::Fail
    } else {
        FindingStatus::Pass
    };

    Ok(Finding::new(
        "ENTRA-CONSENT-001",
        "Identity",
        "Application Consent",
        "User Consent Restrictions",
        "User consent to applications should be restricted or disabled",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-CONSENT-001"))
    .current_value(format!("Assigned policies: {}", consent_strs.join(", ")))
    .expected_value("User consent disabled or restricted to verified publishers only")
    .remediation(
        "Restrict user consent in Entra ID > Enterprise applications > \
         Consent and permissions. Require admin consent for all apps or \
         limit to verified publishers.",
    )
    .build())
}

async fn check_admin_consent_workflow(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policy: serde_json::Value = graph
        .get_json("/v1.0/policies/adminConsentRequestPolicy")
        .await?;

    let is_enabled = policy["isEnabled"].as_bool().unwrap_or(false);

    let status = if is_enabled {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };

    Ok(Finding::new(
        "ENTRA-CONSENT-002",
        "Identity",
        "Application Consent",
        "Admin Consent Workflow",
        "Admin consent workflow should be enabled so users can request access to apps",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-CONSENT-002"))
    .current_value(if is_enabled {
        "Admin consent workflow enabled"
    } else {
        "Admin consent workflow disabled"
    })
    .expected_value("Admin consent workflow enabled")
    .remediation(
        "Enable the admin consent workflow in Entra ID > Enterprise applications > \
         Admin consent requests.",
    )
    .build())
}

async fn check_enterprise_apps(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let sps: Vec<serde_json::Value> = graph
        .get_all("/v1.0/servicePrincipals?$top=999&$select=id,displayName,appId,accountEnabled,appRoleAssignmentRequired,oauth2PermissionScopes,appRoles")
        .await?;

    let total = sps.len();

    // -----------------------------------------------------------------------
    // ENTRA-ENTAPP-001: Total count (informational)
    // -----------------------------------------------------------------------
    findings.push(
        Finding::new(
            "ENTRA-ENTAPP-001",
            "Identity",
            "Enterprise Applications",
            "Enterprise App Count",
            "Inventory of enterprise applications (service principals)",
        )
        .status(FindingStatus::Info)
        .severity(registry.get_severity("ENTRA-ENTAPP-001"))
        .current_value(format!("{total} enterprise applications"))
        .expected_value("Review total for unexpected apps")
        .remediation("Regularly review enterprise applications and remove unused ones.")
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-ENTAPP-002: Disabled apps
    // -----------------------------------------------------------------------
    let disabled: Vec<String> = sps
        .iter()
        .filter(|sp| !sp["accountEnabled"].as_bool().unwrap_or(true))
        .map(|sp| {
            format!(
                "{} ({})",
                sp["displayName"].as_str().unwrap_or("Unknown"),
                sp["appId"].as_str().unwrap_or_default()
            )
        })
        .collect();

    findings.push(
        Finding::new(
            "ENTRA-ENTAPP-002",
            "Identity",
            "Enterprise Applications",
            "Disabled Enterprise Apps",
            "Review disabled enterprise applications",
        )
        .status(if disabled.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Info
        })
        .severity(registry.get_severity("ENTRA-ENTAPP-002"))
        .current_value(format!("{} disabled apps", disabled.len()))
        .expected_value("Review and remove unnecessary disabled apps")
        .remediation("Remove disabled enterprise applications that are no longer needed.")
        .affected_resources(disabled)
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-ENTAPP-003: Assignment required
    // -----------------------------------------------------------------------
    let no_assignment_required: Vec<String> = sps
        .iter()
        .filter(|sp| {
            sp["accountEnabled"].as_bool().unwrap_or(true)
                && !sp["appRoleAssignmentRequired"].as_bool().unwrap_or(false)
        })
        .filter_map(|sp| sp["displayName"].as_str().map(String::from))
        .collect();
    let no_assign_count = no_assignment_required.len();

    findings.push(
        Finding::new(
            "ENTRA-ENTAPP-003",
            "Identity",
            "Enterprise Applications",
            "User Assignment Required",
            "Enterprise apps should require user assignment",
        )
        .status(if no_assign_count == 0 {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .severity(registry.get_severity("ENTRA-ENTAPP-003"))
        .current_value(format!(
            "{no_assign_count} apps do not require user assignment"
        ))
        .expected_value("All enterprise apps require user assignment")
        .remediation(
            "Enable 'User assignment required' on enterprise applications to \
             restrict access to assigned users only.",
        )
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-ENTAPP-004: Overprivileged apps (high-risk permissions)
    // -----------------------------------------------------------------------
    let dangerous_permissions = [
        "Mail.ReadWrite",
        "Files.ReadWrite.All",
        "Directory.ReadWrite.All",
    ];
    // Check app role assignments for dangerous permissions
    let mut overprivileged: Vec<String> = Vec::new();
    for sp in &sps {
        let app_name = sp["displayName"].as_str().unwrap_or("Unknown");
        let sp_id = sp["id"].as_str().unwrap_or_default();

        // Check assigned appRoleAssignments for this SP
        match graph
            .get_all::<serde_json::Value>(&format!(
                "/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
            ))
            .await
        {
            Ok(assignments) => {
                for assignment in &assignments {
                    let resource_name = assignment["resourceDisplayName"]
                        .as_str()
                        .unwrap_or_default();
                    if resource_name == "Microsoft Graph" {
                        // We cannot directly see the permission name in appRoleAssignment,
                        // but we track any Graph app role assignment
                        // A more precise check would resolve the appRoleId
                        // For now, flag apps with many Graph role assignments
                    }
                }
                // Simplified: check the oauth2PermissionScopes names
                if let Some(scopes) = sp["oauth2PermissionScopes"].as_array() {
                    for scope in scopes {
                        let scope_value = scope["value"].as_str().unwrap_or_default();
                        if dangerous_permissions
                            .iter()
                            .any(|p| scope_value.contains(p))
                        {
                            overprivileged.push(format!("{app_name} (scope: {scope_value})"));
                        }
                    }
                }
            }
            Err(_) => { /* skip silently */ }
        }
    }

    findings.push(
        Finding::new(
            "ENTRA-ENTAPP-004",
            "Identity",
            "Enterprise Applications",
            "Overprivileged Apps",
            "Enterprise apps should not have excessive permissions like Mail.ReadWrite, \
             Files.ReadWrite.All, or Directory.ReadWrite.All",
        )
        .status(if overprivileged.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .severity(registry.get_severity("ENTRA-ENTAPP-004"))
        .current_value(format!(
            "{} potentially overprivileged apps",
            overprivileged.len()
        ))
        .expected_value("No apps with high-risk permissions unless justified")
        .remediation(
            "Review and reduce application permissions. Apply least-privilege \
             principles to enterprise application API permissions.",
        )
        .affected_resources(overprivileged)
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-ENTAPP-005: Apps with credentials (secrets/certs)
    // -----------------------------------------------------------------------
    // This would need /v1.0/servicePrincipals/{id}/passwordCredentials but we
    // provide a count-based finding from the earlier data.
    findings.push(
        Finding::new(
            "ENTRA-ENTAPP-005",
            "Identity",
            "Enterprise Applications",
            "Enterprise App Credentials Review",
            "Enterprise apps with credentials should be reviewed regularly",
        )
        .status(FindingStatus::Review)
        .severity(registry.get_severity("ENTRA-ENTAPP-005"))
        .current_value(format!("{total} enterprise apps to review for credentials"))
        .expected_value("All app credentials inventoried and rotated on schedule")
        .remediation(
            "Review enterprise application credentials. Use managed identities \
             where possible and rotate secrets regularly.",
        )
        .build(),
    );

    Ok(findings)
}

async fn check_app_registrations(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let apps: Vec<serde_json::Value> = graph
        .get_all("/v1.0/applications?$select=id,displayName,appId,passwordCredentials,keyCredentials,requiredResourceAccess")
        .await?;

    let total = apps.len();

    // -----------------------------------------------------------------------
    // ENTRA-APPREG-001: App registration count
    // -----------------------------------------------------------------------
    findings.push(
        Finding::new(
            "ENTRA-APPREG-001",
            "Identity",
            "App Registrations",
            "App Registration Count",
            "Inventory of app registrations",
        )
        .status(FindingStatus::Info)
        .severity(registry.get_severity("ENTRA-APPREG-001"))
        .current_value(format!("{total} app registrations"))
        .expected_value("Review for unused registrations")
        .remediation("Regularly review app registrations and remove unused ones.")
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-APPREG-002: Expired or soon-expiring secrets
    // -----------------------------------------------------------------------
    let now = chrono::Utc::now();
    let warning_threshold = chrono::Duration::days(30);
    let mut expired_secrets: Vec<String> = Vec::new();
    let mut expiring_soon: Vec<String> = Vec::new();

    for app in &apps {
        let app_name = app["displayName"].as_str().unwrap_or("Unknown");
        if let Some(creds) = app["passwordCredentials"].as_array() {
            for cred in creds {
                if let Some(end_str) = cred["endDateTime"].as_str() {
                    if let Ok(end_dt) = chrono::DateTime::parse_from_rfc3339(end_str) {
                        let end_utc = end_dt.with_timezone(&chrono::Utc);
                        if end_utc < now {
                            expired_secrets.push(format!("{app_name} (expired: {end_str})"));
                        } else if end_utc - now < warning_threshold {
                            expiring_soon.push(format!("{app_name} (expires: {end_str})"));
                        }
                    }
                }
            }
        }
        if let Some(creds) = app["keyCredentials"].as_array() {
            for cred in creds {
                if let Some(end_str) = cred["endDateTime"].as_str() {
                    if let Ok(end_dt) = chrono::DateTime::parse_from_rfc3339(end_str) {
                        let end_utc = end_dt.with_timezone(&chrono::Utc);
                        if end_utc < now {
                            expired_secrets
                                .push(format!("{app_name} (certificate expired: {end_str})"));
                        } else if end_utc - now < warning_threshold {
                            expiring_soon
                                .push(format!("{app_name} (certificate expires: {end_str})"));
                        }
                    }
                }
            }
        }
    }

    let mut all_affected = expired_secrets.clone();
    all_affected.extend(expiring_soon.clone());

    let status_002 = if expired_secrets.is_empty() && expiring_soon.is_empty() {
        FindingStatus::Pass
    } else if !expired_secrets.is_empty() {
        FindingStatus::Fail
    } else {
        FindingStatus::Warning
    };

    findings.push(
        Finding::new(
            "ENTRA-APPREG-002",
            "Identity",
            "App Registrations",
            "Expired App Secrets/Certificates",
            "App registration secrets and certificates should not be expired",
        )
        .status(status_002)
        .severity(registry.get_severity("ENTRA-APPREG-002"))
        .current_value(format!(
            "{} expired, {} expiring within 30 days",
            expired_secrets.len(),
            expiring_soon.len()
        ))
        .expected_value("No expired secrets or certificates")
        .remediation(
            "Rotate expired secrets and certificates. Set up notifications \
             for upcoming expirations. Prefer certificates over secrets.",
        )
        .affected_resources(all_affected)
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-APPREG-003: Excessive permissions
    // -----------------------------------------------------------------------
    let _dangerous_resource_access = [
        "Mail.ReadWrite",
        "Files.ReadWrite.All",
        "Directory.ReadWrite.All",
    ];
    // Microsoft Graph resource app ID
    let ms_graph_id = "00000003-0000-0000-c000-000000000000";
    let mut excessive_apps: Vec<String> = Vec::new();

    for app in &apps {
        let app_name = app["displayName"].as_str().unwrap_or("Unknown");
        if let Some(required) = app["requiredResourceAccess"].as_array() {
            for resource in required {
                let resource_app = resource["resourceAppId"].as_str().unwrap_or_default();
                if resource_app == ms_graph_id {
                    if let Some(accesses) = resource["resourceAccess"].as_array() {
                        let high_priv_count = accesses.len();
                        if high_priv_count > 10 {
                            excessive_apps
                                .push(format!("{app_name} ({high_priv_count} Graph permissions)"));
                        }
                    }
                }
            }
        }
    }

    findings.push(
        Finding::new(
            "ENTRA-APPREG-003",
            "Identity",
            "App Registrations",
            "Excessive App Permissions",
            "App registrations should follow least-privilege for API permissions",
        )
        .status(if excessive_apps.is_empty() {
            FindingStatus::Pass
        } else {
            FindingStatus::Warning
        })
        .severity(registry.get_severity("ENTRA-APPREG-003"))
        .current_value(format!(
            "{} apps with >10 Graph API permissions",
            excessive_apps.len()
        ))
        .expected_value("Apps should request only necessary permissions")
        .remediation(
            "Review app registration API permissions and remove those that are \
             not required. Apply least-privilege principles.",
        )
        .affected_resources(excessive_apps)
        .build(),
    );

    Ok(findings)
}

async fn check_pim(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    if !tenant.has_p2() {
        return Ok(Finding::new(
            "ENTRA-PIM-001",
            "Identity",
            "Privileged Identity Management",
            "PIM Enabled",
            "Privileged Identity Management requires Entra ID P2 license",
        )
        .status(FindingStatus::NotLicensed)
        .severity(registry.get_severity("ENTRA-PIM-001"))
        .current_value("Entra ID P2 not licensed")
        .expected_value("Entra ID P2 licensed and PIM enabled")
        .remediation(
            "Obtain Entra ID P2 licenses to enable Privileged Identity Management \
             for just-in-time role activation.",
        )
        .build());
    }

    match graph
        .get_all::<serde_json::Value>(
            "/beta/roleManagement/directory/roleAssignmentScheduleInstances",
        )
        .await
    {
        Ok(instances) => {
            let eligible_count = instances.len();
            let status = if eligible_count > 0 {
                FindingStatus::Pass
            } else {
                FindingStatus::Warning
            };

            Ok(Finding::new(
                "ENTRA-PIM-001",
                "Identity",
                "Privileged Identity Management",
                "PIM Enabled",
                "Privileged Identity Management should be used for privileged role management",
            )
            .status(status)
            .severity(registry.get_severity("ENTRA-PIM-001"))
            .current_value(format!(
                "{eligible_count} PIM role assignment schedule instances"
            ))
            .expected_value("PIM enabled with eligible role assignments")
            .remediation(
                "Enable PIM and convert permanent privileged role assignments \
                 to eligible assignments with time-limited activation.",
            )
            .build())
        }
        Err(e) => {
            tracing::warn!("PIM check failed (may lack permissions): {e}");
            Ok(Finding::new(
                "ENTRA-PIM-001",
                "Identity",
                "Privileged Identity Management",
                "PIM Enabled",
                "Could not query PIM status",
            )
            .status(FindingStatus::Review)
            .severity(registry.get_severity("ENTRA-PIM-001"))
            .current_value(format!("Error querying PIM: {e}"))
            .expected_value("PIM enabled with eligible role assignments")
            .remediation(
                "Ensure the assessment service principal has permissions to \
                 read PIM role assignments (RoleManagement.Read.Directory).",
            )
            .build())
        }
    }
}

async fn check_guest_settings(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let auth_policy: serde_json::Value =
        graph.get_json("/v1.0/policies/authorizationPolicy").await?;

    let policy = if let Some(arr) = auth_policy["value"].as_array() {
        arr.first().cloned().unwrap_or(auth_policy.clone())
    } else {
        auth_policy
    };

    // -----------------------------------------------------------------------
    // ENTRA-GUEST-001: Guest user role
    // -----------------------------------------------------------------------
    let guest_role_id = policy["guestUserRoleId"].as_str().unwrap_or_default();
    // Known GUIDs:
    // a0b1b346-... = Guest User (most restrictive)
    // 10dae51f-... = Member (least restrictive, guests same as members)
    // 2af84b1e-... = Restricted Guest (limited)
    let (guest_status, guest_desc) = match guest_role_id {
        "2af84b1e-32c8-42b7-82bc-daa82404023b" => (
            FindingStatus::Pass,
            "Restricted Guest User (most restrictive)",
        ),
        "a0b1b346-4d3e-4e8b-98f8-753987be4970" => {
            (FindingStatus::Pass, "Guest User (standard restrictions)")
        }
        "10dae51f-b6af-4016-8d66-8c2a99b929b3" => (
            FindingStatus::Fail,
            "Member User (guests have same access as members)",
        ),
        _ => (FindingStatus::Review, "Unknown guest role configuration"),
    };

    findings.push(
        Finding::new(
            "ENTRA-GUEST-001",
            "Identity",
            "Guest Access",
            "Guest User Role",
            "Guest users should have restricted access",
        )
        .status(guest_status)
        .severity(registry.get_severity("ENTRA-GUEST-001"))
        .current_value(guest_desc)
        .expected_value("Guest User or Restricted Guest User role")
        .remediation(
            "Set the guest user role to 'Restricted Guest User' in Entra ID > \
             External Identities > External collaboration settings.",
        )
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-GUEST-002: Who can invite guests
    // -----------------------------------------------------------------------
    let allow_invites = policy["allowInvitesFrom"].as_str().unwrap_or("unknown");

    let invite_status = match allow_invites {
        "none" => FindingStatus::Pass,
        "adminsAndGuestInviters" => FindingStatus::Pass,
        "adminsGuestInvitersAndAllMembers" => FindingStatus::Warning,
        "everyone" => FindingStatus::Fail,
        _ => FindingStatus::Review,
    };

    findings.push(
        Finding::new(
            "ENTRA-GUEST-002",
            "Identity",
            "Guest Access",
            "Guest Invitation Settings",
            "Guest invitation permissions should be restricted to admins",
        )
        .status(invite_status)
        .severity(registry.get_severity("ENTRA-GUEST-002"))
        .current_value(format!("allowInvitesFrom: {allow_invites}"))
        .expected_value("adminsAndGuestInviters or none")
        .remediation(
            "Restrict guest invitation permissions to administrators and \
             designated guest inviters.",
        )
        .build(),
    );

    // -----------------------------------------------------------------------
    // ENTRA-GUEST-003: Guest access restrictions summary
    // -----------------------------------------------------------------------
    let allow_email_verified = policy["allowEmailVerifiedUsersToJoinOrganization"]
        .as_bool()
        .unwrap_or(false);

    findings.push(
        Finding::new(
            "ENTRA-GUEST-003",
            "Identity",
            "Guest Access",
            "Email-Verified User Join",
            "Email-verified users joining the tenant should be controlled",
        )
        .status(if allow_email_verified {
            FindingStatus::Warning
        } else {
            FindingStatus::Pass
        })
        .severity(registry.get_severity("ENTRA-GUEST-003"))
        .current_value(if allow_email_verified {
            "Email-verified users CAN join the organization"
        } else {
            "Email-verified users CANNOT join the organization"
        })
        .expected_value("Email-verified user self-service join disabled")
        .remediation(
            "Disable 'Allow email-verified users to join the organization' \
             to prevent unauthorized tenant joins.",
        )
        .build(),
    );

    Ok(findings)
}

async fn check_device_registration(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policy: serde_json::Value = graph
        .get_json("/v1.0/policies/deviceRegistrationPolicy")
        .await?;

    let azure_ad_join = policy["azureADJoin"]["isAdminConfigurable"]
        .as_bool()
        .unwrap_or(false);
    let azure_ad_registration = policy["azureADRegistration"]["isAdminConfigurable"]
        .as_bool()
        .unwrap_or(false);

    let join_allowed_for = policy["azureADJoin"]["allowedToJoin"]
        .as_str()
        .or_else(|| policy["azureADJoin"]["allowedToJoin"]["@odata.type"].as_str())
        .unwrap_or("unknown");

    let current = format!(
        "Entra Join admin-configurable: {azure_ad_join}, \
         Registration admin-configurable: {azure_ad_registration}, \
         Join allowed: {join_allowed_for}"
    );

    let status = if azure_ad_join || azure_ad_registration {
        FindingStatus::Pass
    } else {
        FindingStatus::Review
    };

    Ok(Finding::new(
        "ENTRA-DEVICE-001",
        "Identity",
        "Device Management",
        "Device Registration Policy",
        "Device registration policy should be configured to control which users \
         can join devices to Entra ID",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-DEVICE-001"))
    .current_value(current)
    .expected_value("Device join restricted to authorized users/groups")
    .remediation(
        "Configure device registration policy to restrict Entra ID Join and \
         device registration to authorized users or groups.",
    )
    .build())
}

// ===========================================================================
// New checks: CA-LEGACYAUTH-001 through ENTRA-LINKEDIN-001
// ===========================================================================

async fn check_ca_legacy_auth_blocking(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policies: Vec<serde_json::Value> = graph
        .get_all("/v1.0/identity/conditionalAccess/policies")
        .await?;

    let blocks_legacy = policies.iter().any(|p| {
        let state = p["state"].as_str().unwrap_or("");
        if state != "enabled" {
            return false;
        }
        let client_types = p["conditions"]["clientAppTypes"].as_array();
        let grant = p["grantControls"]["builtInControls"].as_array();
        let has_legacy_type = client_types
            .map(|arr| {
                arr.iter().any(|t| {
                    let s = t.as_str().unwrap_or("");
                    s == "exchangeActiveSync" || s == "other"
                })
            })
            .unwrap_or(false);
        let blocks = grant
            .map(|arr| arr.iter().any(|g| g.as_str() == Some("block")))
            .unwrap_or(false);
        has_legacy_type && blocks
    });

    let status = if blocks_legacy {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };

    Ok(Finding::new(
        "CA-LEGACYAUTH-001",
        "Identity",
        "Conditional Access",
        "Legacy Authentication Blocking",
        "A Conditional Access policy should block legacy/basic authentication protocols",
    )
    .status(status)
    .severity(registry.get_severity("CA-LEGACYAUTH-001"))
    .current_value(if blocks_legacy {
        "Legacy authentication is blocked by CA policy"
    } else {
        "No CA policy blocks legacy authentication"
    })
    .expected_value("Legacy authentication blocked via Conditional Access")
    .remediation(
        "Create a Conditional Access policy that blocks legacy authentication \
         by targeting 'Exchange ActiveSync' and 'Other clients' client app types \
         with a Block grant control.",
    )
    .build())
}

async fn check_ca_mfa_admin(graph: &GraphClient, registry: &ControlRegistry) -> Result<Finding> {
    let policies: Vec<serde_json::Value> = graph
        .get_all("/v1.0/identity/conditionalAccess/policies")
        .await?;

    let requires_mfa_for_admins = policies.iter().any(|p| {
        let state = p["state"].as_str().unwrap_or("");
        if state != "enabled" {
            return false;
        }
        let include_roles = p["conditions"]["users"]["includeRoles"].as_array();
        let has_roles = include_roles.map(|arr| !arr.is_empty()).unwrap_or(false);
        let grant = p["grantControls"]["builtInControls"].as_array();
        let has_mfa = grant
            .map(|arr| arr.iter().any(|g| g.as_str() == Some("mfa")))
            .unwrap_or(false);
        has_roles && has_mfa
    });

    let status = if requires_mfa_for_admins {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };

    Ok(Finding::new(
        "CA-MFA-ADMIN-001",
        "Identity",
        "Conditional Access",
        "MFA Required for Admin Roles",
        "A Conditional Access policy should require MFA for directory admin roles",
    )
    .status(status)
    .severity(registry.get_severity("CA-MFA-ADMIN-001"))
    .current_value(if requires_mfa_for_admins {
        "MFA is required for admin roles via CA policy"
    } else {
        "No CA policy requires MFA for admin roles"
    })
    .expected_value("MFA required for all admin roles via Conditional Access")
    .remediation(
        "Create a Conditional Access policy targeting directory roles \
         (Global Administrator, etc.) with an MFA grant control.",
    )
    .build())
}

async fn check_ca_mfa_all_users(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let policies: Vec<serde_json::Value> = graph
        .get_all("/v1.0/identity/conditionalAccess/policies")
        .await?;

    let requires_mfa_all = policies.iter().any(|p| {
        let state = p["state"].as_str().unwrap_or("");
        if state != "enabled" {
            return false;
        }
        let include_users = p["conditions"]["users"]["includeUsers"].as_array();
        let targets_all = include_users
            .map(|arr| {
                arr.iter().any(|u| {
                    u.as_str()
                        .map(|s| s.eq_ignore_ascii_case("All"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        let grant = p["grantControls"]["builtInControls"].as_array();
        let has_mfa = grant
            .map(|arr| arr.iter().any(|g| g.as_str() == Some("mfa")))
            .unwrap_or(false);
        targets_all && has_mfa
    });

    let status = if requires_mfa_all {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };

    Ok(Finding::new(
        "CA-MFA-ALL-001",
        "Identity",
        "Conditional Access",
        "MFA Required for All Users",
        "A Conditional Access policy should require MFA for all users",
    )
    .status(status)
    .severity(registry.get_severity("CA-MFA-ALL-001"))
    .current_value(if requires_mfa_all {
        "MFA is required for all users via CA policy"
    } else {
        "No CA policy requires MFA for all users"
    })
    .expected_value("MFA required for all users via Conditional Access")
    .remediation(
        "Create a Conditional Access policy targeting 'All users' \
         with an MFA grant control.",
    )
    .build())
}

async fn check_ca_signin_risk(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    if !tenant.has_p2() {
        return Ok(Finding::new(
            "CA-SIGNINRISK-001",
            "Identity",
            "Conditional Access",
            "Sign-In Risk Policy",
            "Sign-in risk-based Conditional Access requires Entra ID P2",
        )
        .status(FindingStatus::NotLicensed)
        .severity(registry.get_severity("CA-SIGNINRISK-001"))
        .current_value("Entra ID P2 not licensed")
        .expected_value("Sign-in risk policy enabled via Conditional Access")
        .remediation(
            "Obtain Entra ID P2 licenses to enable sign-in risk-based \
             Conditional Access policies.",
        )
        .build());
    }

    let policies: Vec<serde_json::Value> = graph
        .get_all("/v1.0/identity/conditionalAccess/policies")
        .await?;

    let has_signin_risk_policy = policies.iter().any(|p| {
        let state = p["state"].as_str().unwrap_or("");
        if state != "enabled" {
            return false;
        }
        let risk_levels = p["conditions"]["signInRiskLevels"].as_array();
        risk_levels
            .map(|arr| {
                arr.iter().any(|l| {
                    let s = l.as_str().unwrap_or("");
                    s == "high" || s == "medium"
                })
            })
            .unwrap_or(false)
    });

    let status = if has_signin_risk_policy {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };

    Ok(Finding::new(
        "CA-SIGNINRISK-001",
        "Identity",
        "Conditional Access",
        "Sign-In Risk Policy",
        "A Conditional Access policy should enforce controls for medium/high sign-in risk",
    )
    .status(status)
    .severity(registry.get_severity("CA-SIGNINRISK-001"))
    .current_value(if has_signin_risk_policy {
        "Sign-in risk policy is configured"
    } else {
        "No sign-in risk policy found"
    })
    .expected_value("CA policy targeting medium and high sign-in risk levels")
    .remediation(
        "Create a Conditional Access policy that requires MFA or blocks access \
         for medium and high sign-in risk levels.",
    )
    .build())
}

async fn check_ca_user_risk(
    graph: &GraphClient,
    tenant: &TenantInfo,
    registry: &ControlRegistry,
) -> Result<Finding> {
    if !tenant.has_p2() {
        return Ok(Finding::new(
            "CA-USERRISK-001",
            "Identity",
            "Conditional Access",
            "User Risk Policy",
            "User risk-based Conditional Access requires Entra ID P2",
        )
        .status(FindingStatus::NotLicensed)
        .severity(registry.get_severity("CA-USERRISK-001"))
        .current_value("Entra ID P2 not licensed")
        .expected_value("User risk policy enabled via Conditional Access")
        .remediation(
            "Obtain Entra ID P2 licenses to enable user risk-based \
             Conditional Access policies.",
        )
        .build());
    }

    let policies: Vec<serde_json::Value> = graph
        .get_all("/v1.0/identity/conditionalAccess/policies")
        .await?;

    let has_user_risk_policy = policies.iter().any(|p| {
        let state = p["state"].as_str().unwrap_or("");
        if state != "enabled" {
            return false;
        }
        let risk_levels = p["conditions"]["userRiskLevels"].as_array();
        risk_levels
            .map(|arr| {
                arr.iter().any(|l| {
                    let s = l.as_str().unwrap_or("");
                    s == "high" || s == "medium"
                })
            })
            .unwrap_or(false)
    });

    let status = if has_user_risk_policy {
        FindingStatus::Pass
    } else {
        FindingStatus::Fail
    };

    Ok(Finding::new(
        "CA-USERRISK-001",
        "Identity",
        "Conditional Access",
        "User Risk Policy",
        "A Conditional Access policy should enforce controls for medium/high user risk",
    )
    .status(status)
    .severity(registry.get_severity("CA-USERRISK-001"))
    .current_value(if has_user_risk_policy {
        "User risk policy is configured"
    } else {
        "No user risk policy found"
    })
    .expected_value("CA policy targeting medium and high user risk levels")
    .remediation(
        "Create a Conditional Access policy that requires password change or blocks \
         access for medium and high user risk levels.",
    )
    .build())
}

async fn check_sspr_enabled(graph: &GraphClient, registry: &ControlRegistry) -> Result<Finding> {
    let auth_policy: serde_json::Value =
        graph.get_json("/v1.0/policies/authorizationPolicy").await?;

    let policy = if let Some(arr) = auth_policy["value"].as_array() {
        arr.first().cloned().unwrap_or(auth_policy.clone())
    } else {
        auth_policy
    };

    let sspr = policy["allowedToUseSSPR"].as_bool();

    let (status, current) = match sspr {
        Some(true) => (FindingStatus::Pass, "SSPR is enabled"),
        Some(false) => (FindingStatus::Fail, "SSPR is disabled"),
        None => (FindingStatus::Review, "SSPR status could not be determined"),
    };

    Ok(Finding::new(
        "ENTRA-SSPR-001",
        "Identity",
        "Password Management",
        "Self-Service Password Reset",
        "Self-Service Password Reset should be enabled for all users",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-SSPR-001"))
    .current_value(current)
    .expected_value("SSPR enabled for all users")
    .remediation(
        "Enable Self-Service Password Reset for all users in Entra ID > \
         Password Reset settings.",
    )
    .build())
}

async fn check_per_user_mfa(graph: &GraphClient, registry: &ControlRegistry) -> Result<Finding> {
    // Per-user MFA is a legacy mechanism. We check if CA policies with MFA exist;
    // if they do, per-user MFA should not be needed. We also attempt to detect
    // per-user MFA usage via the authentication methods report.
    let details: Vec<serde_json::Value> = graph
        .get_all("/v1.0/reports/authenticationMethods/userRegistrationDetails")
        .await?;

    // Check if CA policies with MFA are in place
    let ca_policies: Vec<serde_json::Value> = graph
        .get_all("/v1.0/identity/conditionalAccess/policies")
        .await
        .unwrap_or_default();

    let has_ca_mfa = ca_policies.iter().any(|p| {
        let state = p["state"].as_str().unwrap_or("");
        if state != "enabled" {
            return false;
        }
        let grant = p["grantControls"]["builtInControls"].as_array();
        grant
            .map(|arr| arr.iter().any(|g| g.as_str() == Some("mfa")))
            .unwrap_or(false)
    });

    // Check for users with per-user MFA methods but no CA-based MFA policy
    let per_user_mfa_count = details
        .iter()
        .filter(|d| {
            d["isMfaRegistered"].as_bool().unwrap_or(false)
                && d["methodsRegistered"]
                    .as_array()
                    .map(|arr| {
                        arr.iter().any(|m| {
                            m.as_str()
                                .map(|s| {
                                    s.contains("mobilePhone") || s.contains("alternateMobilePhone")
                                })
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
        })
        .count();

    let (status, current) = if has_ca_mfa {
        (
            FindingStatus::Pass,
            format!(
                "Conditional Access MFA policies are in place. \
                 {per_user_mfa_count} users have legacy phone-based MFA methods registered."
            ),
        )
    } else if per_user_mfa_count > 0 {
        (
            FindingStatus::Warning,
            format!(
                "No CA MFA policy found. {per_user_mfa_count} users appear to use \
                 legacy per-user MFA methods. Consider migrating to Conditional Access."
            ),
        )
    } else {
        (
            FindingStatus::Review,
            "No CA MFA policy found and no legacy per-user MFA detected. \
             MFA enforcement should be reviewed."
                .to_string(),
        )
    };

    Ok(Finding::new(
        "ENTRA-PERUSER-001",
        "Identity",
        "Multi-Factor Authentication",
        "Per-User MFA Status",
        "Per-user MFA is a legacy mechanism; Conditional Access MFA policies are preferred",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-PERUSER-001"))
    .current_value(current)
    .expected_value("MFA enforced via Conditional Access, not per-user MFA")
    .remediation(
        "Migrate from per-user MFA to Conditional Access-based MFA policies. \
         Disable per-user MFA settings once CA policies are in place.",
    )
    .build())
}

async fn check_linkedin_integration(
    graph: &GraphClient,
    registry: &ControlRegistry,
) -> Result<Finding> {
    let auth_policy: serde_json::Value =
        graph.get_json("/v1.0/policies/authorizationPolicy").await?;

    let policy = if let Some(arr) = auth_policy["value"].as_array() {
        arr.first().cloned().unwrap_or(auth_policy.clone())
    } else {
        auth_policy
    };

    // Check for LinkedIn integration indicators in the authorization policy.
    // The v1.0 API may not directly expose LinkedIn settings; we check
    // enabledPreviewFeatures and other available fields as a best effort.
    let linkedin_enabled = policy["enabledPreviewFeatures"]
        .as_array()
        .map(|arr| {
            arr.iter().any(|f| {
                f.as_str()
                    .map(|s| s.to_lowercase().contains("linkedin"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    let (status, current) = if linkedin_enabled {
        (
            FindingStatus::Warning,
            "LinkedIn integration appears to be enabled",
        )
    } else {
        (
            FindingStatus::Review,
            "LinkedIn integration status could not be definitively determined \
             from the authorization policy",
        )
    };

    Ok(Finding::new(
        "ENTRA-LINKEDIN-001",
        "Identity",
        "External Integrations",
        "LinkedIn Account Connection",
        "LinkedIn integration should be reviewed; it may expose organizational data",
    )
    .status(status)
    .severity(registry.get_severity("ENTRA-LINKEDIN-001"))
    .current_value(current)
    .expected_value("LinkedIn integration disabled unless explicitly required")
    .remediation(
        "Review LinkedIn account connections in Entra ID > User Settings > \
         LinkedIn account connections. Disable if not required by the organization.",
    )
    .build())
}
