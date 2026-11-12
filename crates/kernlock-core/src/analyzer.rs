use crate::formats::validate_binary_format;
use crate::models::{
    CommandAnalysisResult, DetectionConfidence, EventCategory, FileScanResult, PolicyConfig,
    RuleMatch, Severity,
};
use crate::rules::{RuleEngine, RuleTarget};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{self, ErrorKind, Read};
use std::path::Path;

pub const DEFAULT_MAX_INSPECT_BYTES: usize = 512 * 1024;

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

/// Streams and analyzes a file of arbitrary size with fixed memory overhead.
///
/// Computes whole-file SHA-256 in blocks while inspecting the initial chunk
/// (up to `DEFAULT_MAX_INSPECT_BYTES`) for headers, entropy, and threat signatures.
pub fn scan_file_streaming(
    path: &Path,
    rules: &RuleEngine,
    policy: &PolicyConfig,
) -> io::Result<FileScanResult> {
    let path_str = path.to_string_lossy().to_string();

    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Refusing to follow symbolic link: {}", path.display()),
            ));
        }
    }

    let mut file = opts.open(path)?;

    let meta = file.metadata()?;
    let ft = meta.file_type();
    if !ft.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Path is not a regular file: {}", path.display()),
        ));
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Refusing to follow reparse point: {}", path.display()),
            ));
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
        }
    }

    scan_stream_reader(&mut file, &path_str, rules, policy)
}

pub fn scan_stream_reader<R: Read>(
    reader: &mut R,
    path_hint: &str,
    rules: &RuleEngine,
    policy: &PolicyConfig,
) -> io::Result<FileScanResult> {
    let mut hasher = Sha256::new();
    let mut inspect_buf = Vec::with_capacity(DEFAULT_MAX_INSPECT_BYTES);
    let mut read_buf = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    // Bounded-memory streaming pattern matching across chunk boundaries throughout the file
    let max_sig_len = rules.max_byte_signature_len().max(256);
    let mut overlap_buf: Vec<u8> = Vec::with_capacity(max_sig_len + 64 * 1024);
    let mut streaming_matches: Vec<RuleMatch> = Vec::new();
    let mut seen_rule_ids = std::collections::HashSet::new();

    loop {
        let n = reader.read(&mut read_buf)?;
        if n == 0 {
            break;
        }
        total_bytes += n as u64;
        let chunk = &read_buf[..n];
        hasher.update(chunk);

        if inspect_buf.len() < DEFAULT_MAX_INSPECT_BYTES {
            let needed = (DEFAULT_MAX_INSPECT_BYTES - inspect_buf.len()).min(n);
            inspect_buf.extend_from_slice(&chunk[..needed]);
        }

        // Extend overlap buffer with current chunk and check signatures across boundaries
        overlap_buf.extend_from_slice(chunk);
        let window_matches = rules.check_byte_signatures_window(&overlap_buf);
        for m in window_matches {
            if seen_rule_ids.insert(m.rule_id.clone()) {
                streaming_matches.push(m);
            }
        }

        // Retain only trailing (max_sig_len - 1) bytes for the next boundary
        let keep_len = (max_sig_len.saturating_sub(1)).min(overlap_buf.len());
        let tail_start = overlap_buf.len() - keep_len;
        overlap_buf.drain(..tail_start);
    }

    let sha256 = hex::encode(hasher.finalize());
    let file_type = detect_file_type(path_hint, &inspect_buf);
    let entropy = shannon_entropy(&inspect_buf);

    let mut result = evaluate_scan_details(
        path_hint,
        sha256,
        total_bytes,
        file_type,
        entropy,
        &inspect_buf,
        rules,
        policy,
    )?;

    // Integrate matches discovered anywhere throughout the stream (including past 512KB and chunk boundaries)
    for m in streaming_matches {
        if !result
            .matches
            .iter()
            .any(|existing| existing.rule_id == m.rule_id)
        {
            result.matches.push(m);
        }
    }

    if !result.matches.is_empty() {
        let score = aggregate_score(&result.matches);
        result.risk_score = score.max(result.risk_score);
        let severity = severity_from_score(result.risk_score);
        if severity > result.severity {
            result.severity = severity;
        }
        if result.threat_name.is_none() {
            result.threat_name = result.matches.first().map(|m| m.rule_name.clone());
        }
        result.is_suspicious =
            result.risk_score >= policy.auto_quarantine_threshold || !result.matches.is_empty();
    }

    Ok(result)
}

#[cfg(unix)]
pub fn scan_file_from_fd(
    raw_fd: std::os::fd::RawFd,
    path_hint: &str,
    rules: &RuleEngine,
    policy: &PolicyConfig,
) -> io::Result<FileScanResult> {
    use std::os::fd::FromRawFd;

    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Rewind file descriptor offset to the start of the file and check for lseek error
    let seek_res = unsafe { libc::lseek(dup_fd, 0, libc::SEEK_SET) };
    if seek_res < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(dup_fd) };
        return Err(err);
    }

    let mut file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
    scan_stream_reader(&mut file, path_hint, rules, policy)
}

#[cfg(not(unix))]
pub fn scan_file_from_fd(
    _raw_fd: i32,
    _path_hint: &str,
    _rules: &RuleEngine,
    _policy: &PolicyConfig,
) -> io::Result<FileScanResult> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "scan_file_from_fd is Unix-only",
    ))
}

#[allow(clippy::too_many_arguments)]
fn evaluate_scan_details(
    path: &str,
    sha256: String,
    size_bytes: u64,
    file_type: String,
    entropy: f64,
    inspect_bytes: &[u8],
    rules: &RuleEngine,
    policy: &PolicyConfig,
) -> io::Result<FileScanResult> {
    if is_path_excluded(path, policy) || policy.excluded_hashes.contains(&sha256) {
        return Ok(FileScanResult {
            path: path.to_string(),
            sha256,
            size_bytes,
            file_type,
            entropy,
            risk_score: 0,
            severity: Severity::Info,
            confidence: DetectionConfidence::Low,
            is_suspicious: false,
            threat_name: None,
            excluded: true,
            matches: Vec::new(),
            summary: "File matches configured policy exclusion.".to_string(),
            scanned_at: Utc::now(),
        });
    }

    let mut matches = Vec::new();

    // 1. Signature database checks (exact hash + byte patterns, including dynamic bundles)
    matches.extend(rules.check_signatures(inspect_bytes, &sha256));

    // 2. Format structure validation & anomaly detection (ELF, PE, Mach-O)
    matches.extend(validate_binary_format(path, inspect_bytes));

    // 3. File path rules
    matches.extend(rules.evaluate(RuleTarget::FilePath, path));

    // 4. File content inspection (lossy UTF-8 for pattern regexes)
    let text_lossy = String::from_utf8_lossy(inspect_bytes);
    matches.extend(rules.evaluate(RuleTarget::FileContent, &text_lossy));

    let lower_type = file_type.to_lowercase();
    if lower_type.contains("script") || lower_type.contains("text") {
        matches.extend(rules.evaluate(RuleTarget::Command, &text_lossy));
    }

    // 5. High entropy heuristic on executable binaries
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

    // Deduplicate matches by rule_id
    let mut seen = std::collections::HashSet::new();
    matches.retain(|m| seen.insert(m.rule_id.clone()));

    let risk_score = aggregate_score(&matches);
    let severity = severity_from_score(risk_score);
    let is_suspicious = risk_score >= 45;

    // Determine confidence and primary threat name
    let has_certain_sig = matches
        .iter()
        .any(|m| m.rule_id.starts_with("KL-HASH-") || m.rule_id == "KL-SIG-EICAR");
    let confidence = if has_certain_sig {
        DetectionConfidence::Certain
    } else if risk_score >= 80 {
        DetectionConfidence::High
    } else if risk_score >= 45 {
        DetectionConfidence::Medium
    } else {
        DetectionConfidence::Low
    };

    let threat_name = matches
        .iter()
        .max_by_key(|m| m.score)
        .map(|m| m.rule_name.clone());

    let summary = if matches.is_empty() {
        format!("Clean ({}, {:.2} bits/byte entropy).", file_type, entropy)
    } else {
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        format!(
            "Flagged {} indicator(s): {} (risk score {}/100, confidence: {:?}).",
            matches.len(),
            names.join("; "),
            risk_score,
            confidence
        )
    };

    Ok(FileScanResult {
        path: path.to_string(),
        sha256,
        size_bytes,
        file_type,
        entropy,
        risk_score,
        severity,
        confidence,
        is_suspicious,
        threat_name,
        excluded: false,
        matches,
        summary,
        scanned_at: Utc::now(),
    })
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

    evaluate_scan_details(
        path, sha256, size_bytes, file_type, entropy, bytes, rules, policy,
    )
    .unwrap_or_else(|_| FileScanResult {
        path: path.to_string(),
        sha256: sha256_hex(bytes),
        size_bytes: bytes.len() as u64,
        file_type: "Error".to_string(),
        entropy: 0.0,
        risk_score: 0,
        severity: Severity::Info,
        confidence: DetectionConfidence::Low,
        is_suspicious: false,
        threat_name: None,
        excluded: false,
        matches: Vec::new(),
        summary: "Analysis failed".to_string(),
        scanned_at: Utc::now(),
    })
}
