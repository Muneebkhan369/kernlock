use crate::models::{EventCategory, RuleMatch, Severity};

pub struct MachoInspection {
    pub is_valid: bool,
    pub format: &'static str,
    pub cputype: &'static str,
    pub anomalies: Vec<RuleMatch>,
}

pub fn inspect_macho(path: &str, bytes: &[u8]) -> Option<MachoInspection> {
    if bytes.len() < 8 {
        return None;
    }

    let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap_or([0; 4]));
    let (format, is_64) = match magic {
        0xfeedface => ("Mach-O 32-bit (Big Endian)", false),
        0xcefaedfe => ("Mach-O 32-bit (Little Endian)", false),
        0xfeedfacf => ("Mach-O 64-bit (Big Endian)", true),
        0xcffaedfe => ("Mach-O 64-bit (Little Endian)", true),
        0xcafebabe => ("Mach-O Universal / Fat Binary", false),
        _ => return None,
    };

    let cputype = if bytes.len() >= 8 {
        let cpu_raw = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or([0; 4]));
        match cpu_raw {
            0x01000007 => "x86_64",
            0x0100000c => "ARM64",
            0x00000007 => "i386",
            0x0000000c => "ARM",
            _ => "Generic/Universal",
        }
    } else {
        "Truncated"
    };

    let mut anomalies = Vec::new();
    if is_64 && bytes.len() < 32 {
        anomalies.push(RuleMatch {
            rule_id: "KL-MACHO-TRUNCATED".to_string(),
            rule_name: "Truncated Mach-O Header".to_string(),
            severity: Severity::Medium,
            score: 50,
            category: EventCategory::File,
            explanation: "Mach-O file header is shorter than the minimum expected 32 bytes.".to_string(),
            evidence: format!("path={}, size={}", path, bytes.len()),
            remediation: "Inspect whether file was truncated during transmission.".to_string(),
        });
    }

    Some(MachoInspection {
        is_valid: anomalies.is_empty(),
        format,
        cputype,
        anomalies,
    })
}
