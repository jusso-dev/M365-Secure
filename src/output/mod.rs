// Output utilities and formatting helpers
use colored::Colorize;

pub fn print_banner() {
    println!();
    println!(
        "{}",
        r#"  __  __ ____   __  ____       _                           "#.bright_cyan()
    );
    println!(
        "{}",
        r#" |  \/  |___ \ / /_| ___| __ _| |___  ___  ___ ___ ___     "#.bright_cyan()
    );
    println!(
        "{}",
        r#" | |\/| | __) | '_ \___ \/ _` | / __|/ _ \/ __/ __/ __|    "#.bright_cyan()
    );
    println!(
        "{}",
        r#" | |  | |/ __/| (_) |__) | (_| | \__ \  __/\__ \__ \__ \   "#.bright_cyan()
    );
    println!(
        "{}",
        r#" |_|  |_|_____|\___/____/ \__,_|_|___/\___||___/___/___/   "#.bright_cyan()
    );
    println!();
    println!(
        "  {} {}",
        "M365 Security Assessment Tool".bright_white().bold(),
        "v1.0.0".dimmed()
    );
    println!("  {}", "Rust CLI - macOS Edition".dimmed());
    println!();
}
