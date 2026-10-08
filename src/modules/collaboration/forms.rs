//! Microsoft Forms checks (FORMS-CONFIG-*), read from Graph `admin/forms/settings`. Moved verbatim from
//! the previous single-file module; the Forms checks themselves are not re-sourced here.

use serde_json::Value;

use crate::assessment::finding::{Finding, FindingStatus};
use crate::assessment::registry::ControlRegistry;
use crate::graph::GraphClient;

pub async fn run(
    graph: &GraphClient,
    registry: &ControlRegistry,
    findings: &mut Vec<Finding>,
    raw_data: &mut Value,
) {
    // --- Forms Settings ---
    let forms_settings = graph.get_json("/beta/admin/forms/settings").await;
    if let Ok(ref forms) = forms_settings {
        raw_data["formsSettings"] = forms.clone();
    }

    // FORMS-CONFIG-001: External sharing restricted
    match &forms_settings {
        Ok(forms) => {
            let external_sharing = forms
                .get("isExternalSharingEnabled")
                .and_then(|v| v.as_bool())
                .or_else(|| {
                    forms
                        .get("externalSharingEnabled")
                        .and_then(|v| v.as_bool())
                });

            let (status, current): (FindingStatus, String) = match external_sharing {
                Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                Some(true) => (FindingStatus::Warning, "Enabled".to_string()),
                None => (FindingStatus::Review, "Setting not found".to_string()),
            };

            findings.push(
                    Finding::new(
                        "FORMS-CONFIG-001",
                        "Collaboration",
                        "Forms Configuration",
                        "External Sharing",
                        "Check that Microsoft Forms external sharing is restricted",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-001"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Restrict external sharing in Microsoft Forms admin settings > External sharing".to_string())
                    .build(),
                );
        }
        Err(e) => {
            findings.push(
                Finding::new(
                    "FORMS-CONFIG-001",
                    "Collaboration",
                    "Forms Configuration",
                    "External Sharing",
                    "Check that Microsoft Forms external sharing is restricted",
                )
                .status(FindingStatus::Unknown)
                .severity(registry.get_severity("FORMS-CONFIG-001"))
                .current_value(format!("Error: {}", e))
                .expected_value("Disabled".to_string())
                .remediation("Verify API permissions and retry the assessment".to_string())
                .build(),
            );
        }
    }

    // FORMS-CONFIG-002: External collaboration settings
    match &forms_settings {
        Ok(forms) => {
            let external_collab = forms
                .get("isExternalCollaborationEnabled")
                .and_then(|v| v.as_bool())
                .or_else(|| {
                    forms
                        .get("externalCollaborationEnabled")
                        .and_then(|v| v.as_bool())
                });

            let (status, current): (FindingStatus, String) = match external_collab {
                Some(false) => (FindingStatus::Pass, "Disabled".to_string()),
                Some(true) => (FindingStatus::Warning, "Enabled".to_string()),
                None => (FindingStatus::Review, "Setting not found".to_string()),
            };

            findings.push(
                    Finding::new(
                        "FORMS-CONFIG-002",
                        "Collaboration",
                        "Forms Configuration",
                        "External Collaboration",
                        "Check that external collaboration settings are appropriately configured for Forms",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-002"))
                    .current_value(current)
                    .expected_value("Disabled".to_string())
                    .remediation("Restrict external collaboration in Microsoft Forms admin settings".to_string())
                    .build(),
                );
        }
        Err(e) => {
            findings.push(
                    Finding::new(
                        "FORMS-CONFIG-002",
                        "Collaboration",
                        "Forms Configuration",
                        "External Collaboration",
                        "Check that external collaboration settings are appropriately configured for Forms",
                    )
                    .status(FindingStatus::Unknown)
                    .severity(registry.get_severity("FORMS-CONFIG-002"))
                    .current_value(format!("Error: {}", e))
                    .expected_value("Disabled".to_string())
                    .remediation("Verify API permissions and retry the assessment".to_string())
                    .build(),
                );
        }
    }

    // FORMS-CONFIG-003: Record respondent names
    match &forms_settings {
        Ok(forms) => {
            let record_names = forms
                .get("isRecordIdentityByDefaultEnabled")
                .and_then(|v| v.as_bool())
                .or_else(|| {
                    forms
                        .get("recordIdentityByDefault")
                        .and_then(|v| v.as_bool())
                });

            let (status, current): (FindingStatus, String) = match record_names {
                Some(true) => (FindingStatus::Pass, "Enabled".to_string()),
                Some(false) => (FindingStatus::Warning, "Disabled".to_string()),
                None => (FindingStatus::Review, "Setting not found".to_string()),
            };

            findings.push(
                Finding::new(
                    "FORMS-CONFIG-003",
                    "Collaboration",
                    "Forms Configuration",
                    "Record Respondent Names",
                    "Check that respondent names are recorded by default in Forms",
                )
                .status(status)
                .severity(registry.get_severity("FORMS-CONFIG-003"))
                .current_value(current)
                .expected_value("Enabled".to_string())
                .remediation(
                    "Enable 'Record name by default' in Microsoft Forms admin settings".to_string(),
                )
                .build(),
            );
        }
        Err(e) => {
            findings.push(
                Finding::new(
                    "FORMS-CONFIG-003",
                    "Collaboration",
                    "Forms Configuration",
                    "Record Respondent Names",
                    "Check that respondent names are recorded by default in Forms",
                )
                .status(FindingStatus::Unknown)
                .severity(registry.get_severity("FORMS-CONFIG-003"))
                .current_value(format!("Error: {}", e))
                .expected_value("Enabled".to_string())
                .remediation("Verify API permissions and retry the assessment".to_string())
                .build(),
            );
        }
    }

    // FORMS-CONFIG-004: Phishing protection enabled
    match &forms_settings {
        Ok(forms) => {
            let phishing_protection = forms
                .get("isInternalPhishingProtectionEnabled")
                .and_then(|v| v.as_bool())
                .or_else(|| {
                    forms
                        .get("internalPhishingProtectionEnabled")
                        .and_then(|v| v.as_bool())
                });

            let (status, current): (FindingStatus, String) = match phishing_protection {
                Some(true) => (FindingStatus::Pass, "Enabled".to_string()),
                Some(false) => (FindingStatus::Fail, "Disabled".to_string()),
                None => (FindingStatus::Review, "Setting not found".to_string()),
            };

            findings.push(
                    Finding::new(
                        "FORMS-CONFIG-004",
                        "Collaboration",
                        "Forms Configuration",
                        "Phishing Protection",
                        "Check that internal phishing protection is enabled for Microsoft Forms",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-004"))
                    .current_value(current)
                    .expected_value("Enabled".to_string())
                    .remediation("Enable phishing protection in Microsoft Forms admin settings to detect and block phishing attempts".to_string())
                    .build(),
                );
        }
        Err(e) => {
            findings.push(
                Finding::new(
                    "FORMS-CONFIG-004",
                    "Collaboration",
                    "Forms Configuration",
                    "Phishing Protection",
                    "Check that internal phishing protection is enabled for Microsoft Forms",
                )
                .status(FindingStatus::Unknown)
                .severity(registry.get_severity("FORMS-CONFIG-004"))
                .current_value(format!("Error: {}", e))
                .expected_value("Enabled".to_string())
                .remediation("Verify API permissions and retry the assessment".to_string())
                .build(),
            );
        }
    }

    // FORMS-CONFIG-005: Bing search integration
    match &forms_settings {
        Ok(forms) => {
            let bing_search = forms
                .get("isBingSearchEnabled")
                .and_then(|v| v.as_bool())
                .or_else(|| forms.get("bingSearchEnabled").and_then(|v| v.as_bool()));

            let (status, current): (FindingStatus, String) = match bing_search {
                Some(false) => (FindingStatus::Pass, "Bing search disabled".to_string()),
                Some(true) => (FindingStatus::Warning, "Bing search enabled".to_string()),
                None => (FindingStatus::Review, "Setting not found".to_string()),
            };

            findings.push(
                    Finding::new(
                        "FORMS-CONFIG-005",
                        "Collaboration",
                        "Forms Configuration",
                        "Bing Search Integration",
                        "Check that Bing search integration is disabled in Microsoft Forms",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-005"))
                    .current_value(current)
                    .expected_value("Bing search disabled".to_string())
                    .remediation("Disable Bing search integration in Microsoft Forms admin settings to prevent data leakage through search suggestions".to_string())
                    .build(),
                );
        }
        Err(e) => {
            findings.push(
                Finding::new(
                    "FORMS-CONFIG-005",
                    "Collaboration",
                    "Forms Configuration",
                    "Bing Search Integration",
                    "Check that Bing search integration is disabled in Microsoft Forms",
                )
                .status(FindingStatus::Unknown)
                .severity(registry.get_severity("FORMS-CONFIG-005"))
                .current_value(format!("Error: {}", e))
                .expected_value("Bing search disabled".to_string())
                .remediation("Verify API permissions and retry the assessment".to_string())
                .build(),
            );
        }
    }

    // FORMS-CONFIG-006: Internal survey sharing
    match &forms_settings {
        Ok(forms) => {
            let internal_sharing = forms
                .get("isInOrgSurveyDefault")
                .and_then(|v| v.as_bool())
                .or_else(|| {
                    forms
                        .get("inOrgFormsPhishingScanEnabled")
                        .and_then(|v| v.as_bool())
                });

            let (status, current): (FindingStatus, String) = match internal_sharing {
                Some(true) => (
                    FindingStatus::Pass,
                    "Internal-only survey default enabled".to_string(),
                ),
                Some(false) => (
                    FindingStatus::Warning,
                    "Internal-only survey default disabled".to_string(),
                ),
                None => (FindingStatus::Review, "Setting not found".to_string()),
            };

            findings.push(
                    Finding::new(
                        "FORMS-CONFIG-006",
                        "Collaboration",
                        "Forms Configuration",
                        "Internal Survey Sharing",
                        "Check that survey sharing defaults to internal-only for Microsoft Forms",
                    )
                    .status(status)
                    .severity(registry.get_severity("FORMS-CONFIG-006"))
                    .current_value(current)
                    .expected_value("Internal-only survey default enabled".to_string())
                    .remediation("Set default survey sharing to internal-only in Microsoft Forms admin settings to prevent unintentional external data collection".to_string())
                    .build(),
                );
        }
        Err(e) => {
            findings.push(
                Finding::new(
                    "FORMS-CONFIG-006",
                    "Collaboration",
                    "Forms Configuration",
                    "Internal Survey Sharing",
                    "Check that survey sharing defaults to internal-only for Microsoft Forms",
                )
                .status(FindingStatus::Unknown)
                .severity(registry.get_severity("FORMS-CONFIG-006"))
                .current_value(format!("Error: {}", e))
                .expected_value("Internal-only survey default enabled".to_string())
                .remediation("Verify API permissions and retry the assessment".to_string())
                .build(),
            );
        }
    }
}
