import { invoke } from "@tauri-apps/api/core";
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

const isTauri =
  typeof window !== "undefined" &&
  (window.location.protocol === "tauri:" || "__TAURI_INTERNALS__" in window);

const BASE_URL = isTauri ? "http://127.0.0.1:17420" : "";
const TOKEN_STORAGE_KEY = "kernlock_api_token";

export function getApiToken(): string {
  if (typeof window === "undefined") return "";
  return sessionStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

export function setApiToken(token: string) {
  if (typeof window !== "undefined") {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, token.trim());
  }
}

export interface DaemonLifecycleStatus {
  running: boolean;
  managed_by_desktop: boolean;
  error: string | null;
}

export async function getDaemonStatus(): Promise<DaemonLifecycleStatus | null> {
  if (!isTauri) return null;
  try {
    return await invoke<DaemonLifecycleStatus>("get_daemon_status");
  } catch {
    return null;
  }
}

export async function restartDaemon(): Promise<DaemonLifecycleStatus | null> {
  if (!isTauri) return null;
  try {
    return await invoke<DaemonLifecycleStatus>("restart_daemon");
  } catch {
    return null;
  }
}

export async function resolveInitialToken(): Promise<string> {
  const existing = getApiToken();
  if (existing) return existing;
  if (isTauri) {
    try {
      const tauriToken = await invoke<string>("get_api_token");
      if (tauriToken) {
        setApiToken(tauriToken);
        return tauriToken;
      }
    } catch {
      // Fall back to manual token prompt if auth.token is not yet created
    }
  }
  return "";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await resolveInitialToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error || `Request failed (${res.status})`);
  }
  return res.json() as Promise<T>;
}

async function requestText(path: string): Promise<string> {
  const token = await resolveInitialToken();
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error || `Request failed (${res.status})`);
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
