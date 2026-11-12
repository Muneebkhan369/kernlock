use crate::models::{
    CommandAnalysisResult, EventCategory, FileScanResult, PolicyConfig, RuleMatch, Severity,
};
use crate::rules::{RuleEngine, RuleTarget};
use chrono::Utc;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn detect_file_type(path: &str, bytes: &[u8]) -> String {
    if bytes.starts_with(b"\x7fELF") {
        return "ELF executable/shared-object".to_string();
    }
    if bytes.starts_with(b"MZ") {
        return "PE/COFF Windows executable".to_string();
    }
    if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        return "Mach-O macOS executable".to_string();
    }
    if bytes.starts_with(b"#!") {
        return "Shell/Interpreter script".to_string();
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return "ZIP/Archive".to_string();
    }
    if bytes.starts_with(b"\x1f\x8b") {
        return "GZIP archive".to_string();
    }
    let lower = path.to_lowercase();
    if lower.ends_with(".sh")
        || lower.ends_with(".bash")
        || lower.ends_with(".zsh")
        || lower.ends_with(".py")
        || lower.ends_with(".js")
        || lower.ends_with(".ps1")
        || lower.ends_with(".bat")
    {
        return "Script".to_string();
    }
    if bytes
        .iter()
        .take(512)
        .all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b))
    {
        return "UTF-8/ASCII text".to_string();
    }
    "Binary data".to_string()
}

pub fn severity_from_score(score: u32) -> Severity {
    match score {
        0 => Severity::Info,
        1..=30 => Severity::Low,
        31..=65 => Severity::Medium,
        66..=84 => Severity::High,
        _ => Severity::Critical,
    }
}

pub fn aggregate_score(matches: &[RuleMatch]) -> u32 {
    if matches.is_empty() {
        return 0;
    }
    let max_score = matches.iter().map(|m| m.score).max().unwrap_or(0);
    let extra = (matches.len().saturating_sub(1) as u32) * 5;
    (max_score + extra).min(100)
}

pub fn is_path_excluded(path: &str, policy: &PolicyConfig) -> bool {
    policy
        .excluded_paths
        .iter()
        .any(|excl| !excl.is_empty() && path.starts_with(excl))
}

/// Statically analyzes a shell command or script string without executing it.
pub fn analyze_command(input: &str, rules: &RuleEngine) -> CommandAnalysisResult {
    let matches = rules.evaluate(RuleTarget::Command, input);
    let risk_score = aggregate_score(&matches);
    let severity = severity_from_score(risk_score);
    let is_suspicious = risk_score >= 40;

    let summary = if matches.is_empty() {
        "No suspicious command or script patterns matched.".to_string()
    } else {
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        format!(
            "Detected {} risk indicator(s): {} (risk score {}/100).",
            matches.len(),
            names.join("; "),
            risk_score
        )
    };

    let preview = if input.chars().count() > 160 {
        format!("{}...", input.chars().take(160).collect::<String>())
    } else {
        input.to_string()
    };

    CommandAnalysisResult {
        input_preview: preview,
        risk_score,
        severity,
        is_suspicious,
        matches,
        summary,
        analyzed_at: Utc::now(),
    }
}

/// Statically analyzes file bytes without executing the file.
pub fn analyze_file_bytes(
    path: &str,
    bytes: &[u8],
    rules: &RuleEngine,
    policy: &PolicyConfig,
) -> FileScanResult {
    let sha256 = sha256_hex(bytes);
    let size_bytes = bytes.len() as u64;
    let file_type = detect_file_type(path, bytes);
    let entropy = shannon_entropy(bytes);

    if is_path_excluded(path, policy) || policy.excluded_hashes.contains(&sha256) {
        return FileScanResult {
            path: path.to_string(),
            sha256,
            size_bytes,
            file_type,
            entropy,
            risk_score: 0,
            severity: Severity::Info,
            is_suspicious: false,
            excluded: true,
            matches: Vec::new(),
            summary: "File matches configured policy exclusion.".to_string(),
            scanned_at: Utc::now(),
        };
    }

    let mut matches = rules.evaluate(RuleTarget::FilePath, path);

    // Inspect text/script content statically
    let text_lossy = String::from_utf8_lossy(bytes);
    matches.extend(rules.evaluate(RuleTarget::FileContent, &text_lossy));

    let lower_type = file_type.to_lowercase();
    if lower_type.contains("script") || lower_type.contains("text") {
        matches.extend(rules.evaluate(RuleTarget::Command, &text_lossy));
    }

    // High entropy heuristic for executables (packed/encrypted payloads),
    // intentionally avoiding false positives on compressed archives.
    if (lower_type.contains("executable") || lower_type.contains("script"))
        && entropy > 7.35
        && size_bytes > 4096
    {
        matches.push(RuleMatch {
            rule_id: "KL-HEUR-ENTROPY".to_string(),
            rule_name: "High Shannon Entropy in Executable/Script".to_string(),
            severity: Severity::Medium,
            score: 45,
            category: EventCategory::File,
            explanation: format!(
                "File entropy is {:.2} bits/byte (> 7.35), which can indicate packing, encryption, or obfuscated embedded payloads.",
                entropy
            ),
            evidence: format!("entropy={:.2}, type={}", entropy, file_type),
            remediation: "Verify the publisher/origin of this binary before running it.".to_string(),
        });
    }

    // Deduplicate by rule_id
    let mut seen = std::collections::HashSet::new();
    matches.retain(|m| seen.insert(m.rule_id.clone()));

    let risk_score = aggregate_score(&matches);
    let severity = severity_from_score(risk_score);
    let is_suspicious = risk_score >= 45;

    let summary = if matches.is_empty() {
        format!("Clean ({}, {:.2} bits/byte entropy).", file_type, entropy)
    } else {
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        format!(
            "Flagged {} indicator(s): {} (risk score {}/100).",
            matches.len(),
            names.join("; "),
            risk_score
        )
    };

    FileScanResult {
        path: path.to_string(),
        sha256,
        size_bytes,
        file_type,
        entropy,
        risk_score,
        severity,
        is_suspicious,
        excluded: false,
        matches,
        summary,
        scanned_at: Utc::now(),
    }
}
