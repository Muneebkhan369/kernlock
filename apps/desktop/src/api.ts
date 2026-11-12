import type {
  AlertStatus,
  CommandAnalysisResult,
  DetectionRuleDef,
  FileScanResult,
  PersistenceEntry,
  PolicyConfig,
  ProcessInfo,
  QuarantineRecord,
  SecurityEvent,
  SecurityReport,
  SystemStatus,
  ThreatAlert,
} from "./types";

const BASE_URL =
  typeof window !== "undefined" && window.location.protocol === "tauri:"
    ? "http://127.0.0.1:17420"
    : "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error || `Request failed (${res.status})`);
  }
  return res.json() as Promise<T>;
}

async function requestText(path: string): Promise<string> {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) {
    throw new Error(`Request failed (${res.status})`);
  }
  return res.text();
}

export const api = {
  getStatus: () => request<SystemStatus>("/api/status"),
  getProcesses: () => request<ProcessInfo[]>("/api/processes"),
  getPersistence: () => request<PersistenceEntry[]>("/api/persistence"),
  scanPath: (path: string) =>
    request<FileScanResult[]>("/api/scan/path", {
      method: "POST",
      body: JSON.stringify({ path }),
    }),
  analyzeCommand: (command: string) =>
    request<CommandAnalysisResult>("/api/analyze/command", {
      method: "POST",
      body: JSON.stringify({ command }),
    }),
  getEvents: () => request<SecurityEvent[]>("/api/events"),
  getAlerts: () => request<ThreatAlert[]>("/api/alerts"),
  updateAlertStatus: (id: string, status: AlertStatus) =>
    request<{ updated: boolean }>(`/api/alerts/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status }),
    }),
  getQuarantine: () => request<QuarantineRecord[]>("/api/quarantine"),
  quarantineFile: (path: string, reason?: string) =>
    request<QuarantineRecord>("/api/quarantine", {
      method: "POST",
      body: JSON.stringify({ path, reason }),
    }),
  restoreQuarantine: (id: string) =>
    request<QuarantineRecord>(`/api/quarantine/${id}/restore`, {
      method: "POST",
    }),
  deleteQuarantine: (id: string) =>
    request<{ deleted: boolean }>(`/api/quarantine/${id}`, {
      method: "DELETE",
    }),
  getPolicy: () => request<PolicyConfig>("/api/policy"),
  updatePolicy: (policy: PolicyConfig) =>
    request<PolicyConfig>("/api/policy", {
      method: "PUT",
      body: JSON.stringify(policy),
    }),
  getRules: () => request<DetectionRuleDef[]>("/api/rules"),
  getReport: () => request<SecurityReport>("/api/report"),
  getReportMarkdown: () => requestText("/api/report/markdown"),
};
