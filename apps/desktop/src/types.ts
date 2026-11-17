export type SecurityMode = "audit" | "protection" | "strict";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "quarantined" | "resolved" | "false_positive";
export type QuarantineStatus = "quarantined" | "restoring" | "restored" | "deleting" | "deleted";
export type ScanMode = "quick" | "full" | "custom";
export type ScanStatus = "queued" | "running" | "completed" | "cancelled" | "failed";
export type DetectionConfidence = "low" | "medium" | "high" | "certain";

export interface ScanProgress {
  scan_id: string;
  mode: ScanMode;
  status: ScanStatus;
  current_path: string;
  files_scanned: number;
  files_skipped: number;
  threats_found: number;
  errors_count: number;
  is_complete: boolean;
  is_cancelled: boolean;
  started_at: string;
  elapsed_seconds: number;
}

export interface ScanJobSummary {
  id: string;
  mode: ScanMode;
  status: ScanStatus;
  started_at: string;
  completed_at: string | null;
  files_scanned: number;
  files_skipped: number;
  threats_found: number;
  errors_count: number;
  target_paths: string[];
  threats: FileScanResult[];
}

export interface ThreatRecord {
  id: string;
  timestamp: string;
  threat_name: string;
  path: string;
  sha256: string;
  severity: Severity;
  confidence: DetectionConfidence;
  risk_score: number;
  action_taken: string;
  quarantine_id: string | null;
}

export interface RuleMatch {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  score: number;
  category: string;
  explanation: string;
  evidence: string;
  remediation: string;
}

export interface CapabilityStatus {
  name: string;
  supported: boolean;
  enforcement_available: boolean;
  active_mode: string;
  details: string;
}

export interface PlatformCapabilities {
  os: string;
  arch: string;
  hostname: string;
  is_privileged: boolean;
  kernel_blocking_available: boolean;
  auto_quarantine_available: boolean;
  active_mode: SecurityMode;
  fallback_reason: string | null;
  capabilities: CapabilityStatus[];
}

export interface PolicyConfig {
  mode: SecurityMode;
  auto_quarantine_threshold: number;
  watch_paths: string[];
  excluded_paths: string[];
  excluded_hashes: string[];
  excluded_processes: string[];
  max_scan_file_size_mb: number;
  updated_at: string;
}

export interface SystemStatus {
  capabilities: PlatformCapabilities;
  policy: PolicyConfig;
  watcher_active: boolean;
  fanotify_active: boolean;
  rules_loaded: number;
  protection_state?: "Active" | "Degraded" | "Failed" | "Unavailable";
  monitor_health?: string;
  state_reason?: string | null;
}

export interface ProcessInfo {
  pid: number;
  ppid: number;
  uid: number;
  name: string;
  exe_path: string;
  cmdline: string;
  cwd: string;
  exe_deleted: boolean;
  risk_score: number;
  risk_flags: string[];
  matches: RuleMatch[];
}

export interface PersistenceEntry {
  id: string;
  source_type: string;
  location: string;
  name: string;
  command_or_target: string;
  enabled: boolean;
  risk_score: number;
  matches: RuleMatch[];
}

export interface FileScanResult {
  path: string;
  sha256: string;
  size_bytes: number;
  file_type: string;
  entropy: number;
  risk_score: number;
  severity: Severity;
  confidence?: DetectionConfidence;
  threat_name?: string | null;
  is_suspicious: boolean;
  excluded: boolean;
  matches: RuleMatch[];
  summary: string;
  scanned_at: string;
}

export interface CommandAnalysisResult {
  input_preview: string;
  risk_score: number;
  severity: Severity;
  is_suspicious: boolean;
  matches: RuleMatch[];
  summary: string;
  analyzed_at: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  target: string;
  risk_score: number;
  action_taken: string;
  rule_ids: string[];
}

export interface ThreatAlert {
  id: string;
  event_id: string;
  timestamp: string;
  severity: Severity;
  title: string;
  explanation: string;
  target: string;
  risk_score: number;
  status: AlertStatus;
  recommended_action: string;
}

export interface QuarantineRecord {
  id: string;
  original_path: string;
  vault_path: string;
  sha256: string;
  original_mode: number;
  size_bytes: number;
  reason: string;
  quarantined_at: string;
  restored_at: string | null;
  status: QuarantineStatus;
}

export interface DetectionRuleDef {
  id: string;
  name: string;
  target: string;
  category: string;
  severity: Severity;
  score: number;
  pattern: string;
  explanation: string;
  remediation: string;
  tags: string[];
}

export interface SecurityReport {
  generated_at: string;
  host_os: string;
  hostname: string;
  security_mode: SecurityMode;
  total_events: number;
  open_alerts: number;
  critical_alerts: number;
  quarantined_files: number;
  suspicious_processes: number | null;
  suspicious_persistence: number | null;
  top_alerts: ThreatAlert[];
  capabilities: PlatformCapabilities;
  recommendations: string[];
}
