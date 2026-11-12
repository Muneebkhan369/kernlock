pub mod elf;
pub mod macho;
pub mod pe;

use crate::models::RuleMatch;

pub fn validate_binary_format(path: &str, bytes: &[u8]) -> Vec<RuleMatch> {
    let mut matches = Vec::new();

    if let Some(elf) = elf::inspect_elf(path, bytes) {
        matches.extend(elf.anomalies);
    } else if let Some(pe) = pe::inspect_pe(path, bytes) {
        matches.extend(pe.anomalies);
    } else if let Some(macho) = macho::inspect_macho(path, bytes) {
        matches.extend(macho.anomalies);
    }

    matches
}
