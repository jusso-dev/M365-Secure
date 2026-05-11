use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::severity::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    Pass,
    Fail,
    Warning,
    Review,
    Info,
    Unknown,
    NotLicensed,
}

impl FindingStatus {
    pub fn css_class(&self) -> &str {
        match self {
            FindingStatus::Pass => "status-pass",
            FindingStatus::Fail => "status-fail",
            FindingStatus::Warning => "status-warning",
            FindingStatus::Review => "status-review",
            FindingStatus::Info => "status-info",
            FindingStatus::Unknown => "status-unknown",
            FindingStatus::NotLicensed => "status-notlicensed",
        }
    }
}

impl fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingStatus::Pass => write!(f, "Pass"),
            FindingStatus::Fail => write!(f, "Fail"),
            FindingStatus::Warning => write!(f, "Warning"),
            FindingStatus::Review => write!(f, "Review"),
            FindingStatus::Info => write!(f, "Info"),
            FindingStatus::Unknown => write!(f, "Unknown"),
            FindingStatus::NotLicensed => write!(f, "Not Licensed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check_id: String,
    pub category: String,
    pub section: String,
    pub setting: String,
    pub description: String,
    pub status: FindingStatus,
    pub severity: Severity,
    pub current_value: String,
    pub expected_value: String,
    pub remediation: String,
    pub framework_mappings: FrameworkMappings,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_resources: Option<Vec<String>>,
}

impl Finding {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        check_id: impl Into<String>,
        category: impl Into<String>,
        section: impl Into<String>,
        setting: impl Into<String>,
        description: impl Into<String>,
    ) -> FindingBuilder {
        FindingBuilder {
            check_id: check_id.into(),
            category: category.into(),
            section: section.into(),
            setting: setting.into(),
            description: description.into(),
            status: FindingStatus::Unknown,
            severity: Severity::Info,
            current_value: String::new(),
            expected_value: String::new(),
            remediation: String::new(),
            framework_mappings: FrameworkMappings::default(),
            details: None,
            affected_resources: None,
        }
    }
}

pub struct FindingBuilder {
    check_id: String,
    category: String,
    section: String,
    setting: String,
    description: String,
    status: FindingStatus,
    severity: Severity,
    current_value: String,
    expected_value: String,
    remediation: String,
    framework_mappings: FrameworkMappings,
    details: Option<serde_json::Value>,
    affected_resources: Option<Vec<String>>,
}

impl FindingBuilder {
    pub fn status(mut self, status: FindingStatus) -> Self {
        self.status = status;
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn current_value(mut self, value: impl Into<String>) -> Self {
        self.current_value = value.into();
        self
    }

    pub fn expected_value(mut self, value: impl Into<String>) -> Self {
        self.expected_value = value.into();
        self
    }

    pub fn remediation(mut self, value: impl Into<String>) -> Self {
        self.remediation = value.into();
        self
    }

    pub fn mappings(mut self, mappings: FrameworkMappings) -> Self {
        self.framework_mappings = mappings;
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn affected_resources(mut self, resources: Vec<String>) -> Self {
        self.affected_resources = Some(resources);
        self
    }

    pub fn build(self) -> Finding {
        Finding {
            check_id: self.check_id,
            category: self.category,
            section: self.section,
            setting: self.setting,
            description: self.description,
            status: self.status,
            severity: self.severity,
            current_value: self.current_value,
            expected_value: self.expected_value,
            remediation: self.remediation,
            framework_mappings: self.framework_mappings,
            timestamp: Utc::now(),
            details: self.details,
            affected_resources: self.affected_resources,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrameworkMappings {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cis: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub nist: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub iso27001: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub soc2: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hipaa: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub pci_dss: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cmmc: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cisa_scuba: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub fedramp: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub essential_eight: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub mitre_attack: Vec<String>,
}
