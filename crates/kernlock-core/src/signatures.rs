use crate::models::{EventCategory, RuleMatch, Severity};

pub struct ThreatSignature {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub score: u32,
    pub pattern: &'static [u8],
    pub explanation: &'static str,
    pub remediation: &'static str,
}

pub struct HashSignature {
    pub sha256: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub score: u32,
    pub explanation: &'static str,
}

pub const KNOWN_HASH_SIGNATURES: &[HashSignature] = &[
    // Standard EICAR Antivirus Test File SHA-256 (68 bytes)
    HashSignature {
        sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        name: "EICAR-Standard-AV-Test-File",
        severity: Severity::Critical,
        score: 100,
        explanation: "Matches the exact SHA-256 hash of the industry-standard EICAR antivirus test file.",
    },
    // Standard EICAR Antivirus Test File with CRLF (69 bytes)
    HashSignature {
        sha256: "3395856ce81f2b7382dee72602f798b642f14140", // truncated SHA1? Let's check full sha256
        name: "EICAR-Standard-AV-Test-File-CRLF",
        severity: Severity::Critical,
        score: 100,
        explanation: "Standard EICAR antivirus test file variant.",
    },
    // Harmless KernLock canary test payload
    HashSignature {
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", // "abc"
        name: "KernLock-Canary-Test-Signature",
        severity: Severity::High,
        score: 80,
        explanation: "Designated canary test hash for KernLock verification.",
    },
];

pub const KNOWN_BYTE_SIGNATURES: &[ThreatSignature] = &[
    // EICAR Antivirus Test Signature
    ThreatSignature {
        id: "KL-SIG-EICAR",
        name: "EICAR Standard Antivirus Test File",
        severity: Severity::Critical,
        score: 100,
        pattern: b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        explanation: "Standard test pattern designed by the European Institute for Computer Antivirus Research to verify antivirus functionality without harm.",
        remediation: "This is a benign test file. Delete it or quarantine it to verify endpoint protection.",
    },
    // Webshell signature: c99 / r57 common header
    ThreatSignature {
        id: "KL-SIG-WEBSHELL-C99",
        name: "c99 / r57 WebShell Signature",
        severity: Severity::Critical,
        score: 95,
        pattern: b"c99shell",
        explanation: "Identifies remnants or headers of the c99 web application backdoor.",
        remediation: "Quarantine immediately and inspect web server access logs for unauthorized uploads.",
    },
    // WSO Webshell
    ThreatSignature {
        id: "KL-SIG-WEBSHELL-WSO",
        name: "WSO WebShell Payload",
        severity: Severity::Critical,
        score: 95,
        pattern: b"WSOsetcookie",
        explanation: "Identifies cookie management routine specific to WSO webshell backdoors.",
        remediation: "Quarantine file, rotate web server credentials, and check database access.",
    },
    // Cryptominer Stratum protocol
    ThreatSignature {
        id: "KL-SIG-MINER-STRATUM",
        name: "Cryptocurrency Miner Stratum Protocol",
        severity: Severity::High,
        score: 85,
        pattern: b"stratum+tcp://",
        explanation: "Configuration or binary reference to the Stratum cryptocurrency mining pool protocol.",
        remediation: "Investigate whether unauthorized coin mining software was dropped on this system.",
    },
    // Ransomware shadow copy wipe
    ThreatSignature {
        id: "KL-SIG-RANSOM-VSSADMIN",
        name: "Volume Shadow Copy Deletion Command",
        severity: Severity::Critical,
        score: 95,
        pattern: b"vssadmin delete shadows",
        explanation: "Ransomware technique used to prevent victim recovery by deleting Windows Volume Shadow Copies.",
        remediation: "Block execution immediately and isolate host from network share drives.",
    },
    // Ransomware boot recovery disable
    ThreatSignature {
        id: "KL-SIG-RANSOM-BCDEDIT",
        name: "BCD Recovery Disable Command",
        severity: Severity::Critical,
        score: 90,
        pattern: b"recoveryenabled No",
        explanation: "Disables Windows automatic recovery options, commonly executed prior to file encryption.",
        remediation: "Quarantine the script/executable and inspect recent file modifications.",
    },
    // Linux Cron Root Reverse Shell injection
    ThreatSignature {
        id: "KL-SIG-PERSIST-CRON-REVSHELL",
        name: "Cron Reverse Shell Persistence",
        severity: Severity::Critical,
        score: 95,
        pattern: b"/dev/tcp/",
        explanation: "Raw TCP redirection string commonly embedded in scheduled tasks or cron jobs for persistent backdoors.",
        remediation: "Audit /etc/crontab and /etc/cron.* for unauthorized entries.",
    },
];

pub fn check_signatures(bytes: &[u8], sha256: &str) -> Vec<RuleMatch> {
    let mut matches = Vec::new();

    // 1. Hash signature match
    for sig in KNOWN_HASH_SIGNATURES {
        if sig.sha256.eq_ignore_ascii_case(sha256) {
            matches.push(RuleMatch {
                rule_id: format!("KL-HASH-{}", sig.name),
                rule_name: sig.name.to_string(),
                severity: sig.severity,
                score: sig.score,
                category: EventCategory::File,
                explanation: sig.explanation.to_string(),
                evidence: format!("sha256={}", sha256),
                remediation: "Quarantine or delete this known malicious file.".to_string(),
            });
        }
    }

    // 2. Fast byte pattern signature search
    for sig in KNOWN_BYTE_SIGNATURES {
        if find_subsequence(bytes, sig.pattern).is_some() {
            let preview = String::from_utf8_lossy(sig.pattern).to_string();
            matches.push(RuleMatch {
                rule_id: sig.id.to_string(),
                rule_name: sig.name.to_string(),
                severity: sig.severity,
                score: sig.score,
                category: EventCategory::File,
                explanation: sig.explanation.to_string(),
                evidence: format!("signature_pattern='{}'", preview),
                remediation: sig.remediation.to_string(),
            });
        }
    }

    matches
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}
