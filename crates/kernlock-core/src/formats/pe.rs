use crate::models::{EventCategory, RuleMatch, Severity};

pub struct PeInspection {
    pub is_valid: bool,
    pub machine: &'static str,
    pub section_count: usize,
    pub anomalies: Vec<RuleMatch>,
}

pub fn inspect_pe(path: &str, bytes: &[u8]) -> Option<PeInspection> {
    if bytes.len() < 64 || !bytes.starts_with(b"MZ") {
        return None;
    }

    // Offset 0x3C gives the offset to the PE signature
    let pe_offset = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
    if pe_offset + 24 > bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    let coff_offset = pe_offset + 4;
    let machine_raw = u16::from_le_bytes(bytes[coff_offset..coff_offset + 2].try_into().unwrap_or([0; 2]));
    let machine = match machine_raw {
        0x014c => "x86 (32-bit)",
        0x8664 => "x64 (AMD64)",
        0xaa64 => "ARM64",
        0x0200 => "Intel Itanium",
        _ => "Unknown PE Architecture",
    };

    let num_sections = u16::from_le_bytes(bytes[coff_offset + 2..coff_offset + 4].try_into().unwrap_or([0; 2])) as usize;
    let opt_header_size = u16::from_le_bytes(bytes[coff_offset + 16..coff_offset + 18].try_into().unwrap_or([0; 2])) as usize;

    let mut anomalies = Vec::new();
    let sections_start = coff_offset + 20 + opt_header_size;

    if sections_start + num_sections * 40 <= bytes.len() {
        for i in 0..num_sections.min(32) {
            let s_off = sections_start + i * 40;
            let name_raw = &bytes[s_off..s_off + 8];
            let name = String::from_utf8_lossy(name_raw).trim_matches('\0').trim().to_lowercase();
            let characteristics = u32::from_le_bytes(bytes[s_off + 36..s_off + 40].try_into().unwrap_or([0; 4]));

            // W+X section: IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000)
            if (characteristics & 0xA0000000) == 0xA0000000 {
                anomalies.push(RuleMatch {
                    rule_id: "KL-PE-WX-SECTION".to_string(),
                    rule_name: "PE W+X (Writable & Executable) Section".to_string(),
                    severity: Severity::High,
                    score: 75,
                    category: EventCategory::File,
                    explanation: format!("PE section '{}' is marked as both writable and executable, commonly indicating an executable unpacker, cryptor, or code cave injection.", name),
                    evidence: format!("section='{}', characteristics={:#x}", name, characteristics),
                    remediation: "Verify executable origin; legitimate signed Windows executables avoid W+X sections.".to_string(),
                });
            }

            // Known packer section names
            let known_packers = [".upx0", ".upx1", ".aspack", ".vmp0", ".themida", ".mpress"];
            for p in &known_packers {
                if name.contains(p) {
                    anomalies.push(RuleMatch {
                        rule_id: "KL-PE-PACKER-SECTION".to_string(),
                        rule_name: format!("PE Known Packer Section ('{}')", name),
                        severity: Severity::Medium,
                        score: 55,
                        category: EventCategory::File,
                        explanation: format!("PE section '{}' matches signature of a known executable packer or protector, often used to conceal malicious payload logic.", name),
                        evidence: format!("path={}, section='{}'", path, name),
                        remediation: "Inspect binary provenance and verify digital signature validity.".to_string(),
                    });
                    break;
                }
            }
        }
    }

    Some(PeInspection {
        is_valid: anomalies.is_empty(),
        machine,
        section_count: num_sections,
        anomalies,
    })
}
