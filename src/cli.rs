use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "m365-assess",
    version = env!("CARGO_PKG_VERSION"),
    about = "Microsoft 365 Security Assessment CLI Tool",
    long_about = "A comprehensive security assessment tool for Microsoft 365 tenants.\nAnalyzes identity, email, collaboration, device management, and security configurations\nagainst CIS, NIST, ISO 27001, SOC 2, and other compliance frameworks."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Tenant ID (Azure AD / Entra ID tenant)
    #[arg(long, global = true, env = "M365_TENANT_ID")]
    pub tenant_id: Option<String>,

    /// Client ID (App Registration)
    #[arg(long, global = true, env = "M365_CLIENT_ID")]
    pub client_id: Option<String>,

    /// Cloud environment
    #[arg(long, global = true, default_value = "commercial", value_parser = ["commercial", "gcchigh", "dod"])]
    pub cloud: String,

    /// Verbose logging
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Output format for structured logging (json, text)
    #[arg(long, global = true, default_value = "text")]
    pub log_format: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Authenticate to Microsoft 365
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },

    /// Run security assessment scan
    Scan {
        #[command(subcommand)]
        action: ScanCommands,
    },

    /// Generate reports from assessment data
    Report {
        #[command(subcommand)]
        action: ReportCommands,
    },

    /// Show tool information
    Info,
}

#[derive(Subcommand, Debug)]
pub enum AuthCommands {
    /// Login to Microsoft 365 tenant
    Login {
        /// Use client credentials flow (requires --client-secret)
        #[arg(long)]
        client_secret: Option<String>,

        /// Authentication scopes (comma-separated)
        #[arg(long)]
        scopes: Option<String>,
    },

    /// Logout and clear cached tokens
    Logout,

    /// Show current authentication status
    Status,
}

#[derive(Subcommand, Debug)]
pub enum ScanCommands {
    /// Run full assessment (all default modules)
    Full {
        /// Output directory
        #[arg(short, long, default_value = "M365-Assessment")]
        output: String,

        /// Output formats (comma-separated: html,csv,json)
        #[arg(short, long, default_value = "html,csv,json")]
        format: String,

        /// Quick scan (Critical and High severity only)
        #[arg(long)]
        quick: bool,

        /// Include opt-in modules (comma-separated: inventory,soc2,powerbi,value)
        #[arg(long)]
        include: Option<String>,
    },

    /// Run specific assessment module
    Module {
        /// Module name (identity, exchange, security, collaboration, intune, licensing, hybrid, powerbi, purview, inventory, soc2, value)
        name: String,

        /// Output directory
        #[arg(short, long, default_value = "M365-Assessment")]
        output: String,

        /// Output formats
        #[arg(short, long, default_value = "html,csv,json")]
        format: String,
    },

    /// List available modules
    List,
}

#[derive(Subcommand, Debug)]
pub enum ReportCommands {
    /// Generate report from existing JSON results
    Generate {
        /// Path to assessment JSON results file
        #[arg(short, long)]
        input: String,

        /// Output directory
        #[arg(short, long, default_value = "M365-Assessment")]
        output: String,

        /// Output formats (comma-separated)
        #[arg(short, long, default_value = "html")]
        format: String,
    },
}
