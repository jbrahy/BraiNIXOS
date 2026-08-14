use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let repo_root = find_repo_root().expect("Could not find repository root");

    let kani_proofs = find_kani_proofs(&repo_root);
    let fuzz_targets = find_fuzz_targets(&repo_root);
    let invariants = extract_invariants(&repo_root);

    let coverage = map_proofs_to_invariants(&kani_proofs, &fuzz_targets, &invariants);

    let ci_features = ci_enabled_features(&repo_root);

    print_report(
        &invariants,
        &coverage,
        &kani_proofs,
        &fuzz_targets,
        &ci_features,
    );
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
    /// The cargo feature this harness is gated behind, if any.
    ///
    /// A harness that exists is not a harness that runs. Eight in this tree
    /// sit behind `long-proofs` because they have never been observed to
    /// terminate, and counting them as coverage would be a claim nothing can
    /// falsify -- which the north star forbids in exactly those words.
    gate: Option<String>,
    #[allow(dead_code)]
    lines: Vec<String>,
}

impl Proof {
    /// Whether CI runs this harness.
    ///
    /// Ungated harnesses always run. A gated one runs only if some CI step
    /// enables its feature -- which is read out of the workflow rather than
    /// assumed, so a harness gated behind a feature nobody enables is reported
    /// as unrun even though it looks exactly like one that is.
    fn runs_in_ci(&self, ci_features: &[String]) -> bool {
        match &self.gate {
            None => true,
            Some(gate) => ci_features.iter().any(|enabled| enabled == gate),
        }
    }
}

/// The cargo features `.github/workflows/ci.yml` enables anywhere.
///
/// `deny-allocation` and `long-proofs` look identical in the source -- both are
/// `#[cfg(feature = ...)]` on a `#[kani::proof]`. The difference is that CI has
/// a job for one and not the other, and that difference lives in the workflow.
fn ci_enabled_features(repo_root: &Path) -> Vec<String> {
    let path = repo_root.join(".github/workflows/ci.yml");
    let Ok(workflow) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut features = Vec::new();
    for line in workflow.lines() {
        let mut rest = line;
        while let Some(at) = rest.find("--features") {
            let after = &rest[at.saturating_add("--features".len())..];
            let name: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == ',')
                .collect();
            for feature in name.split(',').filter(|f| !f.is_empty()) {
                if !features.iter().any(|existing| existing == feature) {
                    features.push(feature.to_string());
                }
            }
            rest = after;
        }
    }
    features
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
            // A `#[cfg(feature = "...")]` may sit above the proof attribute or
            // between it and the function; both orders appear in this tree.
            let gate_above = lines[i.saturating_sub(3)..i]
                .iter()
                .rev()
                .find_map(|candidate| extract_feature_gate(candidate));

            // Look for the function definition in the next few lines
            for j in (i+1)..std::cmp::min(i+10, lines.len()) {
                let gate_below = lines[(i + 1)..=j]
                    .iter()
                    .find_map(|c| extract_feature_gate(c));
                if let Some(fn_name) = extract_function_name(lines[j]) {
                    let proof = Proof {
                        name: fn_name,
                        file: path.display().to_string(),
                        gate: gate_above.clone().or(gate_below),
                        lines: vec![content.to_string()],
                    };
                    proofs.push(proof);
                    break;
                }
            }
        }
    }
}

/// The feature named by a `#[cfg(feature = "name")]` attribute, if this line is one.
fn extract_feature_gate(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with("#[cfg(") || !trimmed.contains("feature") {
        return None;
    }
    let after = trimmed.split("feature").nth(1)?;
    let mut quoted = after.split('"');
    let _before = quoted.next()?;
    quoted.next().map(std::string::ToString::to_string)
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

    // The auditor. INV-AUDIT is "observes and reports and does nothing else",
    // and its record is where that claim is kept honest: bounded pressure
    // (INV-AUD-003) and a decode that refuses rather than inventing an event
    // (INV-AUD-001).
    if lower.starts_with("auditd_audit_") {
        return Some("INV-AUDIT".to_string());
    }

    // The confined tenant. INV-MODEL's content is the capability manifest and
    // the per-session KV binding: "the model physically cannot name a
    // capability it was not granted", and no session can name another's cache.
    // Routed before the parser families below because `inferd_model_*` proofs
    // are about confinement rather than about decoding bytes.
    if lower.starts_with("inferd_model_") {
        return Some("INV-MODEL".to_string());
    }

    // Hostile-input parser proofs. SECURITY_INVARIANTS.md §15's INV-PARSE-001..004
    // roll up under INV-SERVE, so an ADT proof lands there — except the bounds
    // and allocation proofs, which are what INV-MEM asserts about every parser.
    if lower.contains("adt") || lower.contains("device_tree") {
        if lower.contains("buffer") || lower.contains("bounds") || lower.contains("allocation") {
            return Some("INV-MEM".to_string());
        }
        return Some("INV-SERVE".to_string());
    }

    // The two BSP v2 network-facing crates: the wire decoder (brainix-bsp) and
    // the key schedule plus record layer (brainix-transport-crypto). Both are
    // hostile-input parsers, so §15's INV-PARSE-001..004 roll up under INV-SERVE
    // per the mapping table at SECURITY_INVARIANTS.md line 33. Two families of
    // proof belong elsewhere and are routed before that default:
    //
    //   - buffer, bound, overflow and zeroization proofs are what INV-MEM
    //     asserts about every parser and about every secret;
    //   - the capability grant of §7.2 and the enumerated authority bytes of
    //     row A1 are INV-AUTH-009's, not INV-SERVE's.
    //
    // No new identifier is introduced: all three are existing NORTH_STAR
    // headline invariants.
    if lower.starts_with("bsp_") || lower.starts_with("transport_crypto_") {
        if lower.contains("buffer")
            || lower.contains("bounds")
            || lower.contains("overflow")
            || lower.contains("stream")
            || lower.contains("zeroiz")
            || lower.contains("erases")
        {
            return Some("INV-MEM".to_string());
        }
        if lower.contains("authority")
            || lower.contains("capability")
            || lower.contains("illegal_state")
        {
            return Some("INV-AUTH".to_string());
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

    // The BSP v2 network-facing targets, named before the generic rules below
    // so the mapping is deliberate rather than an accident of substring order:
    // "transport" would otherwise catch the two transport-crypto targets by way
    // of the transportd rule, which is a different component.
    if lower.contains("bsp_decoder") || lower.contains("transport_crypto") {
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
    ci_features: &[String],
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

    let running = kani_proofs
        .iter()
        .filter(|proof| proof.runs_in_ci(ci_features))
        .count();
    let gated = kani_proofs.len().saturating_sub(running);
    println!("- **Kani Proofs**: {} ({} run in CI, {} gated)", kani_proofs.len(), running, gated);
    println!("- **Fuzz Targets**: {}\n", fuzz_targets.len());

    if gated > 0 {
        println!("### Harnesses that exist but do not run\n");
        println!("A harness behind a cargo feature is not part of the gate on a pull");
        println!("request. Counting one as coverage would be a claim nothing can");
        println!("falsify, so they are listed here and excluded from the figure above.\n");
        for proof in kani_proofs.iter().filter(|proof| !proof.runs_in_ci(ci_features)) {
            let gate = proof.gate.clone().unwrap_or_else(|| "unknown".to_string());
            println!("- `{}` ({}) — behind `{}`", proof.name, component_label(&proof.file), gate);
        }
        println!();
    }

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
                let mark = match &proof.gate {
                    Some(gate) if !proof.runs_in_ci(ci_features) => {
                        format!(" — GATED behind `{gate}`, does not run in CI")
                    }
                    Some(gate) => format!(" — behind `{gate}`, enabled by a CI job"),
                    None => String::new(),
                };
                println!("    - `{}` ({}){}", proof.name, component_label(&proof.file), mark);
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
