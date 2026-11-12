use crate::models::{EventCategory, RuleMatch, Severity};

pub struct ElfInspection {
    pub is_valid: bool,
    pub class: &'static str,
    pub machine: &'static str,
    pub anomalies: Vec<RuleMatch>,
}

pub fn inspect_elf(path: &str, bytes: &[u8]) -> Option<ElfInspection> {
    if bytes.len() < 16 || !bytes.starts_with(b"\x7fELF") {
        return None;
    }

    let class_byte = bytes[4];
    let class = match class_byte {
        1 => "ELF32",
        2 => "ELF64",
        _ => "Invalid ELF Class",
    };

    let data_byte = bytes[5];
    let is_little_endian = data_byte == 1;

    let machine = if bytes.len() >= 20 {
        let m = if is_little_endian {
            u16::from_le_bytes([bytes[18], bytes[19]])
        } else {
            u16::from_be_bytes([bytes[18], bytes[19]])
        };
        match m {
            3 => "x86 (i386)",
            62 => "x86_64 (AMD64)",
            40 => "ARM",
            183 => "AArch64 (ARM64)",
            243 => "RISC-V",
            _ => "Unknown Machine",
        }
    } else {
        "Truncated"
    };

    let mut anomalies = Vec::new();

    if class_byte != 1 && class_byte != 2 {
        anomalies.push(RuleMatch {
            rule_id: "KL-ELF-MALFORMED-CLASS".to_string(),
            rule_name: "Malformed ELF Class Byte".to_string(),
            severity: Severity::Medium,
            score: 50,
            category: EventCategory::File,
            explanation: format!("ELF file has invalid class byte {class_byte}; may be a corrupted or obfuscated binary."),
            evidence: format!("path={}, class_byte={}", path, class_byte),
            remediation: "Verify binary authenticity before execution.".to_string(),
        });
    }

    // Inspect 64-bit ELF Program Headers for W+X (Writable and Executable) memory segments
    if class_byte == 2 && bytes.len() >= 64 {
        let phoff = if is_little_endian {
            u64::from_le_bytes(bytes[32..40].try_into().unwrap_or([0; 8]))
        } else {
            u64::from_be_bytes(bytes[32..40].try_into().unwrap_or([0; 8]))
        } as usize;

        let phentsize = if is_little_endian {
            u16::from_le_bytes(bytes[54..56].try_into().unwrap_or([0; 2]))
        } else {
            u16::from_be_bytes(bytes[54..56].try_into().unwrap_or([0; 2]))
        } as usize;

        let phnum = if is_little_endian {
            u16::from_le_bytes(bytes[56..58].try_into().unwrap_or([0; 2]))
        } else {
            u16::from_be_bytes(bytes[56..58].try_into().unwrap_or([0; 2]))
        } as usize;

        if phentsize >= 56 && phnum > 0 && phoff > 0 {
            for i in 0..phnum.min(64) {
                let offset = phoff + i * phentsize;
                if offset + 56 <= bytes.len() {
                    let p_type = if is_little_endian {
                        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]))
                    } else {
                        u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]))
                    };
                    let p_flags = if is_little_endian {
                        u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap_or([0; 4]))
                    } else {
                        u32::from_be_bytes(bytes[offset + 4..offset + 8].try_into().unwrap_or([0; 4]))
                    };

                    // PT_LOAD = 1, PF_X = 1, PF_W = 2 => (p_flags & 3) == 3 is W+X
                    if p_type == 1 && (p_flags & 0x3) == 0x3 {
                        anomalies.push(RuleMatch {
                            rule_id: "KL-ELF-WX-SEGMENT".to_string(),
                            rule_name: "ELF W+X (Writable & Executable) Segment Detected".to_string(),
                            severity: Severity::High,
                            score: 75,
                            category: EventCategory::File,
                            explanation: "The binary contains a segment marked as both writable and executable, a common trait of unpackers, runtime self-modification, and shellcode loaders.".to_string(),
                            evidence: format!("segment_index={}, p_type=PT_LOAD, p_flags={:#x} (PF_W | PF_X)", i, p_flags),
                            remediation: "Audit this binary; legitimate modern software enforces W^X (write XOR execute).".to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    Some(ElfInspection {
        is_valid: anomalies.is_empty(),
        class,
        machine,
        anomalies,
    })
}
