//! Keeps the control registry and the module code honest with each other.
//!
//! - Every check id the modules can emit must be defined in the registry (base file or an overlay).
//! - Every registry check flagged `hasAutomatedCheck: true` must be emitted somewhere in `src/modules`.
//! - Ids are unique, well-formed, and carry a name, category and severity.
//!
//! Check ids are recognised in source as string literals shaped like `ENTRA-CA-001`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Check ids referenced as literals in module source.
fn ids_in_source() -> BTreeMap<String, Vec<String>> {
    let mut files = Vec::new();
    rust_files(&root().join("src/modules"), &mut files);
    let re = regex::Regex::new(r#""([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+-\d{3})""#).unwrap();
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        let name = file.strip_prefix(root()).unwrap().display().to_string();
        for cap in re.captures_iter(&text) {
            found
                .entry(cap[1].to_string())
                .or_default()
                .push(name.clone());
        }
    }
    found
}

#[derive(serde::Deserialize)]
struct RegistryFile {
    checks: Vec<serde_json::Value>,
}

/// Registry entries, base file first then overlays in name order (later wins).
fn registry() -> BTreeMap<String, serde_json::Value> {
    let controls = root().join("controls");
    let mut files = vec![controls.join("registry.json")];
    let overlay_dir = controls.join("registry.d");
    if overlay_dir.is_dir() {
        let mut overlays: Vec<_> = fs::read_dir(&overlay_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        overlays.sort();
        files.extend(overlays);
    }
    let mut out = BTreeMap::new();
    let mut seen_in_file: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let parsed: RegistryFile = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not valid registry JSON: {e}", file.display()));
        let fname = file.file_name().unwrap().to_string_lossy().to_string();
        for check in parsed.checks {
            let id = check["checkId"].as_str().unwrap_or_default().to_string();
            assert!(!id.is_empty(), "{fname}: a check has no checkId");
            assert!(
                seen_in_file
                    .entry(fname.clone())
                    .or_default()
                    .insert(id.clone()),
                "{fname}: duplicate checkId {id}"
            );
            out.insert(id, check);
        }
    }
    out
}

#[test]
fn registry_entries_are_well_formed() {
    let re = regex::Regex::new(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+-\d{3}$").unwrap();
    for (id, check) in registry() {
        assert!(re.is_match(&id), "{id}: check ids look like ENTRA-CA-001");
        assert!(
            check["name"].as_str().is_some_and(|n| n.len() > 3),
            "{id}: needs a name"
        );
        assert!(
            check["category"].as_str().is_some_and(|n| !n.is_empty()),
            "{id}: needs a category"
        );
        if let Some(sev) = check["impactRating"]["severity"].as_str() {
            assert!(
                ["Critical", "High", "Medium", "Low", "Info"].contains(&sev),
                "{id}: unknown severity {sev}"
            );
        }
        if let Some(frameworks) = check["frameworks"].as_object() {
            for (key, value) in frameworks {
                assert!(
                    value["controlId"].as_str().is_some(),
                    "{id}: frameworks.{key} needs a controlId string"
                );
            }
        }
    }
}

#[test]
fn every_emitted_check_is_in_the_registry() {
    let registry = registry();
    let missing: Vec<String> = ids_in_source()
        .into_iter()
        .filter(|(id, _)| !registry.contains_key(id))
        .map(|(id, files)| format!("{id} (in {})", files.join(", ")))
        .collect();
    assert!(
        missing.is_empty(),
        "check ids used in src/modules but not defined in controls/registry.json or controls/registry.d/:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn every_automated_registry_check_is_implemented() {
    let source = ids_in_source();
    let orphaned: Vec<String> = registry()
        .into_iter()
        .filter(|(_, c)| c["hasAutomatedCheck"].as_bool().unwrap_or(false))
        .filter(|(id, _)| !source.contains_key(id))
        .map(|(id, _)| id)
        .collect();
    assert!(
        orphaned.is_empty(),
        "registry checks flagged hasAutomatedCheck but never emitted by src/modules (set hasAutomatedCheck to false or implement them):\n  {}",
        orphaned.join("\n  ")
    );
}
