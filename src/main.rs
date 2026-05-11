mod assessment;
mod auth;
mod cli;
mod compliance;
mod graph;
mod modules;
mod output;
mod report;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use assessment::engine::AssessmentEngine;
use assessment::registry::ControlRegistry;
use auth::{AuthConfig, AuthManager, AuthMethod, CloudEnvironment};
use cli::{AuthCommands, Cli, Commands, ReportCommands, ScanCommands};
use compliance::frameworks::FrameworkLibrary;
use compliance::mapping::ComplianceMapper;
use graph::GraphClient;
use modules::ScanConfig;
use report::ReportGenerator;

const DEFAULT_CLIENT_ID: &str = "14d82eec-204b-4c2f-b7e8-296a70dab67e";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    if cli.log_format == "json" {
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_target(false)
            .init();
    }

    let tenant_id = cli.tenant_id.clone();
    let client_id = cli.client_id.clone();
    let cloud = cli.cloud.clone();

    match cli.command {
        Commands::Auth { action } => handle_auth(action, tenant_id, client_id, &cloud).await,
        Commands::Scan { action } => handle_scan(action, tenant_id, client_id, &cloud).await,
        Commands::Report { action } => handle_report(action).await,
        Commands::Info => handle_info(),
    }
}

async fn handle_auth(
    action: AuthCommands,
    tenant_id: Option<String>,
    client_id: Option<String>,
    cloud_str: &str,
) -> Result<()> {
    let tenant_id = tenant_id.ok_or_else(|| {
        anyhow::anyhow!("--tenant-id is required. Set M365_TENANT_ID env var or pass --tenant-id")
    })?;
    let client_id = client_id.unwrap_or_else(|| DEFAULT_CLIENT_ID.to_string());
    let cloud = parse_cloud(cloud_str);

    match action {
        AuthCommands::Login { client_secret, .. } => {
            output::print_banner();

            let method = if let Some(secret) = client_secret {
                AuthMethod::ClientCredentials {
                    client_id: client_id.clone(),
                    client_secret: secret,
                }
            } else {
                AuthMethod::DeviceCode
            };

            let config = AuthConfig {
                tenant_id,
                client_id,
                method,
                cloud_environment: cloud,
            };

            let auth = AuthManager::new(config);
            auth.login().await?;
            println!(
                "{}",
                "Successfully authenticated to Microsoft 365".bright_green()
            );
            Ok(())
        }
        AuthCommands::Logout => {
            let config = AuthConfig {
                tenant_id,
                client_id,
                method: AuthMethod::DeviceCode,
                cloud_environment: cloud,
            };
            let auth = AuthManager::new(config);
            auth.logout().await?;
            println!("{}", "Logged out and cleared cached tokens".bright_green());
            Ok(())
        }
        AuthCommands::Status => {
            let config = AuthConfig {
                tenant_id: tenant_id.clone(),
                client_id,
                method: AuthMethod::DeviceCode,
                cloud_environment: cloud,
            };
            let auth = AuthManager::new(config);
            match auth.get_token().await {
                Ok(_) => {
                    println!(
                        "{} Authenticated to tenant {}",
                        "OK".bright_green(),
                        tenant_id
                    );
                }
                Err(_) => {
                    println!(
                        "{} Not authenticated. Run `m365-assess auth login`",
                        "NOT AUTHENTICATED".bright_red()
                    );
                }
            }
            Ok(())
        }
    }
}

async fn handle_scan(
    action: ScanCommands,
    tenant_id: Option<String>,
    client_id: Option<String>,
    cloud_str: &str,
) -> Result<()> {
    match action {
        ScanCommands::Full {
            output,
            format,
            quick,
            include,
        } => {
            output::print_banner();

            let tenant_id = tenant_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--tenant-id is required"))?;
            let client_id = client_id
                .clone()
                .unwrap_or_else(|| DEFAULT_CLIENT_ID.to_string());
            let cloud = parse_cloud(cloud_str);

            // Authenticate
            let auth_config = AuthConfig {
                tenant_id,
                client_id,
                method: AuthMethod::DeviceCode,
                cloud_environment: cloud,
            };
            let auth = AuthManager::new(auth_config);
            auth.login().await?;

            // Build scan config
            let mut scan_config = ScanConfig {
                quick_scan: quick,
                output_formats: format.split(',').map(|s| s.trim().to_string()).collect(),
                ..Default::default()
            };

            if let Some(include_str) = include {
                for module in include_str.split(',') {
                    match module.trim() {
                        "inventory" => scan_config.include_inventory = true,
                        "soc2" => scan_config.include_soc2 = true,
                        "powerbi" => scan_config.include_powerbi = true,
                        "value" => scan_config.include_value = true,
                        _ => println!(
                            "{} Unknown opt-in module: {}",
                            "WARN:".bright_yellow(),
                            module
                        ),
                    }
                }
            }

            // Load controls registry
            let controls_dir = find_controls_dir()?;
            let registry = ControlRegistry::load(&controls_dir)?;

            // Create graph client and engine
            let graph = GraphClient::new(auth);
            let engine = AssessmentEngine::new(graph, registry);

            // Run assessment
            let summary = engine.run_full_assessment(&scan_config).await?;

            // Generate reports
            let findings = engine.get_findings().await;

            // Load compliance frameworks and map
            let frameworks_dir = controls_dir.join("frameworks");
            let library = FrameworkLibrary::load(&frameworks_dir)?;
            let compliance_results = ComplianceMapper::map_findings(&findings, &library);

            let output_dir = PathBuf::from(&output);
            std::fs::create_dir_all(&output_dir)?;

            let generated = ReportGenerator::generate(
                &output_dir,
                &summary,
                &findings,
                &compliance_results,
                &scan_config.output_formats,
            )?;

            println!("\n{}", "Reports generated:".bright_green().bold());
            for file in &generated {
                println!("  {}", file);
            }

            Ok(())
        }

        ScanCommands::Module {
            name,
            output,
            format,
        } => {
            output::print_banner();

            let tenant_id = tenant_id.ok_or_else(|| anyhow::anyhow!("--tenant-id is required"))?;
            let client_id = client_id.unwrap_or_else(|| DEFAULT_CLIENT_ID.to_string());
            let cloud = parse_cloud(cloud_str);

            let auth_config = AuthConfig {
                tenant_id,
                client_id,
                method: AuthMethod::DeviceCode,
                cloud_environment: cloud,
            };
            let auth = AuthManager::new(auth_config);
            auth.login().await?;

            let scan_config = ScanConfig {
                modules: vec![name.clone()],
                output_formats: format.split(',').map(|s| s.trim().to_string()).collect(),
                ..Default::default()
            };

            let controls_dir = find_controls_dir()?;
            let registry = ControlRegistry::load(&controls_dir)?;
            let graph = GraphClient::new(auth);
            let output_dir = PathBuf::from(&output);
            let engine = AssessmentEngine::new(graph, registry);

            let summary = engine.run_module_assessment(&name, &scan_config).await?;

            let findings = engine.get_findings().await;
            let frameworks_dir = controls_dir.join("frameworks");
            let library = FrameworkLibrary::load(&frameworks_dir)?;
            let compliance_results = ComplianceMapper::map_findings(&findings, &library);

            let generated = ReportGenerator::generate(
                &output_dir,
                &summary,
                &findings,
                &compliance_results,
                &scan_config.output_formats,
            )?;

            println!("\n{}", "Reports generated:".bright_green().bold());
            for file in &generated {
                println!("  {}", file);
            }

            Ok(())
        }

        ScanCommands::List => {
            output::print_banner();
            println!("{}", "Available Assessment Modules:".bright_white().bold());
            println!();
            println!("  {} (default)", "Default Modules:".bright_cyan());
            println!("    identity      Entra ID / Azure AD security (MFA, CA, admins, apps)");
            println!("    licensing     License inventory and allocation");
            println!("    exchange      Exchange Online / email security");
            println!("    security      Defender, DLP, compliance policies");
            println!("    collaboration SharePoint, Teams, Forms");
            println!("    intune        Device management and compliance");
            println!("    hybrid        Entra Connect sync status");
            println!();
            println!("  {}", "Opt-in Modules:".bright_cyan());
            println!("    powerbi       Power BI tenant security settings");
            println!("    purview       Data lifecycle and retention");
            println!("    inventory     Detailed M&A object inventory");
            println!("    soc2          SOC 2 readiness assessment");
            println!("    value         License utilization and feature adoption");
            println!();
            println!(
                "  {} m365-assess scan full --include inventory,soc2",
                "Example:".dimmed()
            );
            println!("  {} m365-assess scan module identity", "Example:".dimmed());
            Ok(())
        }
    }
}

async fn handle_report(action: ReportCommands) -> Result<()> {
    match action {
        ReportCommands::Generate {
            input,
            output,
            format,
        } => {
            output::print_banner();

            let data = std::fs::read_to_string(&input)?;
            let json: serde_json::Value = serde_json::from_str(&data)?;

            let summary: assessment::engine::AssessmentSummary =
                serde_json::from_value(json["summary"].clone())?;
            let findings: Vec<assessment::finding::Finding> =
                serde_json::from_value(json["findings"].clone())?;
            let compliance_results: Vec<compliance::mapping::ComplianceResult> =
                serde_json::from_value(json["compliance"].clone()).unwrap_or_default();

            let output_dir = PathBuf::from(&output);
            let formats: Vec<String> = format.split(',').map(|s| s.trim().to_string()).collect();

            let generated = ReportGenerator::generate(
                &output_dir,
                &summary,
                &findings,
                &compliance_results,
                &formats,
            )?;

            println!("{}", "Reports generated:".bright_green().bold());
            for file in &generated {
                println!("  {}", file);
            }

            Ok(())
        }
    }
}

fn handle_info() -> Result<()> {
    output::print_banner();
    println!("{}", "Tool Information:".bright_white().bold());
    println!("  Version:    1.0.0");
    println!("  Platform:   macOS (Rust)");
    println!("  Runtime:    Tokio async");
    println!("  Auth:       OAuth2 Device Code / Client Credentials");
    println!("  Storage:    macOS Keychain / Encrypted file");
    if let Ok(controls_dir) = find_controls_dir() {
        if let Ok(registry) = ControlRegistry::load(&controls_dir) {
            println!("  Controls:   {}", registry.control_count());
        }
    }
    println!();
    println!("{}", "Compliance Frameworks:".bright_white().bold());
    println!("  CIS Microsoft 365 Foundations v6 (E3/E5 L1/L2)");
    println!("  NIST 800-53 Rev 5 / NIST CSF 2.0");
    println!("  ISO 27001:2022");
    println!("  SOC 2 TSC");
    println!("  PCI DSS v4.0.1");
    println!("  HIPAA Security Rule");
    println!("  CMMC 2.0");
    println!("  CISA SCuBA");
    println!("  FedRAMP");
    println!("  Essential Eight");
    println!("  MITRE ATT&CK");
    println!("  CIS Controls v8");
    println!("  Entra ID STIG / DISA STIG");
    println!();
    println!("{}", "Required Permissions:".bright_white().bold());
    for scope in auth::GRAPH_SCOPES {
        println!("  - {}", scope);
    }
    Ok(())
}

fn parse_cloud(s: &str) -> CloudEnvironment {
    match s.to_lowercase().as_str() {
        "gcchigh" | "gcc-high" | "gcc_high" => CloudEnvironment::GccHigh,
        "dod" => CloudEnvironment::Dod,
        _ => CloudEnvironment::Commercial,
    }
}

fn find_controls_dir() -> Result<PathBuf> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    let candidates = vec![
        PathBuf::from("controls"),
        PathBuf::from("./controls"),
        exe_dir
            .clone()
            .map(|d| d.join("controls"))
            .unwrap_or_default(),
        exe_dir.map(|d| d.join("../controls")).unwrap_or_default(),
    ];

    for candidate in candidates {
        if candidate.exists() && candidate.join("registry.json").exists() {
            return Ok(candidate);
        }
    }

    let fallback = PathBuf::from("controls");
    if fallback.exists() {
        return Ok(fallback);
    }

    anyhow::bail!(
        "Controls directory not found. Ensure 'controls/' directory exists with registry.json"
    )
}
