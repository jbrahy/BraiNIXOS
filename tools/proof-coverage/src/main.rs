use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let repo_root = find_repo_root().expect("Could not find repository root");

    let kani_proofs = find_kani_proofs(&repo_root);
    let fuzz_targets = find_fuzz_targets(&repo_root);
    let invariants = extract_invariants(&repo_root);

    let coverage = map_proofs_to_invariants(&kani_proofs, &fuzz_targets, &invariants);

    print_report(&invariants, &coverage, &kani_proofs, &fuzz_targets);
}

fn find_repo_root() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        if current.join("docs/NORTH_STAR.md").exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

#[derive(Debug, Clone)]
struct Proof {
    name: String,
    file: String,
    #[allow(dead_code)]
    lines: Vec<String>,
}

#[derive(Debug, Clone)]
struct FuzzTarget {
    name: String,
    #[allow(dead_code)]
    file: String,
}

#[derive(Debug, Clone)]
struct Invariant {
    id: String,
    description: String,
}

#[derive(Debug)]
struct Coverage {
    invariant_proofs: HashMap<String, Vec<Proof>>,
    invariant_fuzz: HashMap<String, Vec<FuzzTarget>>,
    uncovered: Vec<String>,
}

fn find_kani_proofs(repo_root: &Path) -> Vec<Proof> {
    let mut proofs = Vec::new();

    if let Ok(entries) = fs::read_dir(repo_root.join("src")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_directory_for_proofs(&path, &mut proofs);
            }
        }
    }

    proofs
}

fn scan_directory_for_proofs(dir: &Path, proofs: &mut Vec<Proof>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.ends_with("vendor") {
                continue;
            }
            if path.is_dir() {
                scan_directory_for_proofs(&path, proofs);
            } else if path.extension().map_or(false, |ext| ext == "rs") {
                if let Ok(content) = fs::read_to_string(&path) {
                    extract_proofs_from_file(&path, &content, proofs);
                }
            }
        }
    }
}

fn extract_proofs_from_file(path: &Path, content: &str, proofs: &mut Vec<Proof>) {
    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if line.contains("#[kani::proof]") {
            // Look for the function definition in the next few lines
            for j in (i+1)..std::cmp::min(i+10, lines.len()) {
                if let Some(fn_name) = extract_function_name(lines[j]) {
                    let proof = Proof {
                        name: fn_name,
                        file: path.display().to_string(),
                        lines: vec![content.to_string()],
                    };
                    proofs.push(proof);
                    break;
                }
            }
        }
    }
}

fn extract_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("fn ") {
        if let Some(end) = trimmed.find('(') {
            return Some(trimmed[3..end].trim().to_string());
        }
    }
    None
}

fn find_fuzz_targets(repo_root: &Path) -> Vec<FuzzTarget> {
    let mut targets = Vec::new();
    let fuzz_dir = repo_root.join("fuzz/fuzz_targets");

    if let Ok(entries) = fs::read_dir(&fuzz_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "rs") {
                if let Some(name) = path.file_stem() {
                    targets.push(FuzzTarget {
                        name: name.to_string_lossy().to_string(),
                        file: path.display().to_string(),
                    });
                }
            }
        }
    }

    targets.sort_by(|a, b| a.name.cmp(&b.name));
    targets
}

fn extract_invariants(repo_root: &Path) -> Vec<Invariant> {
    let mut invariants = Vec::new();
    let north_star_path = repo_root.join("docs/NORTH_STAR.md");

    if let Ok(content) = fs::read_to_string(north_star_path) {
        let lines: Vec<&str> = content.lines().collect();

        // Find invariants section
        for (i, line) in lines.iter().enumerate() {
            if line.contains("## Invariants") {
                // Parse invariants from the section
                for j in (i+1)..std::cmp::min(i+50, lines.len()) {
                    let line = lines[j].trim();
                    // NORTH_STAR.md emboldens the identifier: "- **INV-MEM**: ...".
                    // Matching only the unemboldened form silently found nothing,
                    // which reported every invariant as absent rather than as
                    // uncovered.
                    if line.starts_with("- INV-") || line.starts_with("- **INV-") {
                        if let Some((id, desc)) = parse_invariant_line(line) {
                            invariants.push(Invariant { id, description: desc });
                        }
                    }
                    if line.starts_with("##") && j > i + 2 {
                        break;
                    }
                }
                break;
            }
        }
    }

    invariants
}

fn parse_invariant_line(line: &str) -> Option<(String, String)> {
    let line = line.trim_start_matches("- ");
    if let Some(colon_pos) = line.find(':') {
        // The identifier is the leading INV-… token; NORTH_STAR.md wraps it in
        // bold markers and may append a parenthetical, neither of which is part
        // of the name.
        let id: String = line[..colon_pos]
            .trim()
            .trim_start_matches('*')
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '-')
            .collect();
        let description = line[colon_pos+1..].trim().to_string();
        return Some((id, description));
    }
    None
}

fn map_proofs_to_invariants(
    kani_proofs: &[Proof],
    fuzz_targets: &[FuzzTarget],
    invariants: &[Invariant],
) -> Coverage {
    let mut invariant_proofs: HashMap<String, Vec<Proof>> = HashMap::new();
    let mut invariant_fuzz: HashMap<String, Vec<FuzzTarget>> = HashMap::new();

    // Initialize all invariants
    for inv in invariants {
        invariant_proofs.insert(inv.id.clone(), Vec::new());
        invariant_fuzz.insert(inv.id.clone(), Vec::new());
    }

    // Map Kani proofs
    for proof in kani_proofs {
        let inv = infer_invariant_from_proof(&proof.name);
        if let Some(inv_id) = inv {
            if let Some(entry) = invariant_proofs.get_mut(&inv_id) {
                entry.push(proof.clone());
            }
        }
    }

    // Map fuzz targets
    for target in fuzz_targets {
        let inv = infer_invariant_from_fuzz_target(&target.name);
        if let Some(inv_id) = inv {
            if let Some(entry) = invariant_fuzz.get_mut(&inv_id) {
                entry.push(target.clone());
            }
        }
    }

    // Find uncovered invariants
    let mut uncovered = Vec::new();
    for inv in invariants {
        let has_proof = invariant_proofs.get(&inv.id).map_or(false, |v| !v.is_empty());
        let has_fuzz = invariant_fuzz.get(&inv.id).map_or(false, |v| !v.is_empty());
        if !has_proof && !has_fuzz {
            uncovered.push(inv.id.clone());
        }
    }
    uncovered.sort();

    Coverage {
        invariant_proofs,
        invariant_fuzz,
        uncovered,
    }
}

fn infer_invariant_from_proof(proof_name: &str) -> Option<String> {
    let lower = proof_name.to_lowercase();

    // Hostile-input parser proofs. SECURITY_INVARIANTS.md §15's INV-PARSE-001..004
    // roll up under INV-SERVE, so an ADT proof lands there — except the bounds
    // and allocation proofs, which are what INV-MEM asserts about every parser.
    if lower.contains("adt") || lower.contains("device_tree") {
        if lower.contains("buffer") || lower.contains("bounds") || lower.contains("allocation") {
            return Some("INV-MEM".to_string());
        }
        return Some("INV-SERVE".to_string());
    }

    if lower.contains("rights") || lower.contains("authority") || lower.contains("revocation") || lower.contains("capability") || lower.contains("derivation") {
        Some("INV-AUTH".to_string())
    } else if lower.contains("memory") || lower.contains("out_of_bounds") || lower.contains("cslot") || lower.contains("budget") {
        Some("INV-MEM".to_string())
    } else if lower.contains("attestation") || lower.contains("boot") || lower.contains("csprng") {
        Some("INV-BOOT".to_string())
    } else {
        None
    }
}

fn infer_invariant_from_fuzz_target(target_name: &str) -> Option<String> {
    let lower = target_name.to_lowercase();

    // Check the ADT first: its target name mentions firmware device trees, and
    // §15's INV-PARSE-001..004 roll up under INV-SERVE.
    if lower.contains("adt") || lower.contains("device_tree") {
        return Some("INV-SERVE".to_string());
    }

    // Check for IPC first, since "ipc_boundary" should map to IPC not Memory
    if lower.contains("ipc_boundary") {
        Some("INV-IPC".to_string())
    } else if lower.contains("capability") {
        Some("INV-AUTH".to_string())
    } else if lower.contains("memory") && !lower.contains("ipc") {
        Some("INV-MEM".to_string())
    } else if lower.contains("ipc") || lower.contains("boundary") {
        Some("INV-IPC".to_string())
    } else if lower.contains("bootloader") || lower.contains("multiboot") || lower.contains("tpm") || lower.contains("quote") {
        Some("INV-BOOT".to_string())
    } else if lower.contains("ipd") || lower.contains("ingress") || lower.contains("ip_packet") || lower.contains("transport") || lower.contains("ethernet") {
        Some("INV-SERVE".to_string())
    } else {
        None
    }
}

/// Labels a proof by the crate that holds it, not by its file name alone.
///
/// Every verify crate names its harness file `lib.rs`, so the bare file name
/// cannot tell `capability-verify` from `adt-verify` and a reader cannot see
/// which component a proof belongs to.
fn component_label(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let file = parts.last().copied().unwrap_or(path);
    match parts.len().checked_sub(3).and_then(|at| parts.get(at)) {
        Some(crate_dir) => format!("{}/{}", crate_dir, file),
        None => file.to_string(),
    }
}

fn print_report(
    invariants: &[Invariant],
    coverage: &Coverage,
    kani_proofs: &[Proof],
    fuzz_targets: &[FuzzTarget],
) {
    println!("# BraiNIX Proof Coverage Report\n");

    println!("## Summary\n");
    let total_invariants = invariants.len();
    let covered_invariants = total_invariants - coverage.uncovered.len();
    let coverage_percentage = (covered_invariants as f64 / total_invariants as f64) * 100.0;

    println!("- **Total Invariants**: {}", total_invariants);
    println!("- **Covered Invariants**: {} / {}", covered_invariants, total_invariants);
    println!("- **Coverage Percentage**: {:.1}%", coverage_percentage);
    println!("- **Target (80% bar)**: Need {} more invariants covered\n",
             ((total_invariants as f64 * 0.8) as usize).saturating_sub(covered_invariants));

    println!("- **Kani Proofs**: {}", kani_proofs.len());
    println!("- **Fuzz Targets**: {}\n", fuzz_targets.len());

    println!("## Invariant Coverage Details\n");

    for invariant in invariants {
        let empty_proofs = Vec::new();
        let empty_fuzz = Vec::new();
        let proofs = coverage.invariant_proofs.get(&invariant.id).unwrap_or(&empty_proofs);
        let fuzz = coverage.invariant_fuzz.get(&invariant.id).unwrap_or(&empty_fuzz);
        let total = proofs.len() + fuzz.len();

        let status = if total > 0 { "✓" } else { "✗" };
        println!("### {} {} - {}", status, invariant.id, invariant.description);

        if !proofs.is_empty() {
            println!("  **Kani Proofs** ({}):", proofs.len());
            for proof in proofs {
                println!("    - `{}` ({})", proof.name, component_label(&proof.file));
            }
        }

        if !fuzz.is_empty() {
            println!("  **Fuzz Targets** ({}):", fuzz.len());
            for target in fuzz {
                println!("    - `{}`", target.name);
            }
        }

        if total == 0 {
            println!("  **Status**: No coverage artifacts found");
        }
        println!();
    }

    println!("## Artifacts List\n");

    println!("### Kani Proofs ({})\n", kani_proofs.len());
    for proof in kani_proofs {
        println!("- `{}` ({})", proof.name, component_label(&proof.file));
    }
    println!();

    println!("### Fuzz Targets ({})\n", fuzz_targets.len());
    for target in fuzz_targets {
        println!("- `{}`", target.name);
    }

    if !coverage.uncovered.is_empty() {
        println!("\n## Uncovered Invariants\n");
        for inv_id in &coverage.uncovered {
            if let Some(inv) = invariants.iter().find(|i| i.id == *inv_id) {
                println!("- **{}**: {}", inv.id, inv.description);
            }
        }
    }
}
