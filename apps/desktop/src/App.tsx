import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Archive,
  FileSearch,
  FileText,
  Layers,
  Lock,
  Settings,
  Shield,
  Terminal,
} from "lucide-react";
import { api } from "./api";
import type {
  CommandAnalysisResult,
  DetectionRuleDef,
  FileScanResult,
  PersistenceEntry,
  PolicyConfig,
  ProcessInfo,
  QuarantineRecord,
  SecurityEvent,
  SecurityMode,
  SecurityReport,
  SystemStatus,
  ThreatAlert,
} from "./types";

type Tab =
  | "overview"
  | "scanner"
  | "processes"
  | "persistence"
  | "alerts"
  | "quarantine"
  | "policies"
  | "reports";

export default function App() {
  const [tab, setTab] = useState<Tab>("overview");
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [persistence, setPersistence] = useState<PersistenceEntry[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [quarantine, setQuarantine] = useState<QuarantineRecord[]>([]);
  const [rules, setRules] = useState<DetectionRuleDef[]>([]);
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [reportMd, setReportMd] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  // Scanner & Analyzer state
  const [scanPathInput, setScanPathInput] = useState<string>("/tmp");
  const [scanResults, setScanResults] = useState<FileScanResult[]>([]);
  const [cmdInput, setCmdInput] = useState<string>("");
  const [cmdResult, setCmdResult] = useState<CommandAnalysisResult | null>(null);

  // Policy draft state
  const [policyDraft, setPolicyDraft] = useState<PolicyConfig | null>(null);
  const [newExclPath, setNewExclPath] = useState<string>("");
  const [newWatchPath, setNewWatchPath] = useState<string>("");

  async function refreshOverview() {
    try {
      setError(null);
      const [s, a, e, q] = await Promise.all([
        api.getStatus(),
        api.getAlerts(),
        api.getEvents(),
        api.getQuarantine(),
      ]);
      setStatus(s);
      setPolicyDraft(s.policy);
      setAlerts(a);
      setEvents(e);
      setQuarantine(q);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    refreshOverview();
  }, []);

  async function loadTab(nextTab: Tab) {
    setTab(nextTab);
    setError(null);
    setLoading(true);
    try {
      if (nextTab === "overview") {
        await refreshOverview();
      } else if (nextTab === "processes") {
        setProcesses(await api.getProcesses());
      } else if (nextTab === "persistence") {
        setPersistence(await api.getPersistence());
      } else if (nextTab === "alerts") {
        const [a, e] = await Promise.all([api.getAlerts(), api.getEvents()]);
        setAlerts(a);
        setEvents(e);
      } else if (nextTab === "quarantine") {
        setQuarantine(await api.getQuarantine());
      } else if (nextTab === "policies") {
        const [p, r] = await Promise.all([api.getPolicy(), api.getRules()]);
        setPolicyDraft(p);
        setRules(r);
      } else if (nextTab === "reports") {
        const [rep, md] = await Promise.all([api.getReport(), api.getReportMarkdown()]);
        setReport(rep);
        setReportMd(md);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleModeChange(mode: SecurityMode) {
    if (!policyDraft) return;
    try {
      const updated = await api.updatePolicy({ ...policyDraft, mode });
      setPolicyDraft(updated);
      await refreshOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleScanPath() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.scanPath(scanPathInput);
      setScanResults(res);
      await refreshOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleAnalyzeCmd() {
    if (!cmdInput.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.analyzeCommand(cmdInput);
      setCmdResult(res);
      await refreshOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleQuarantine(path: string, reason: string) {
    try {
      await api.quarantineFile(path, reason);
      await refreshOverview();
      if (scanPathInput) {
        setScanResults((prev) => prev.filter((item) => item.path !== path));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleRestore(id: string) {
    try {
      await api.restoreQuarantine(id);
      setQuarantine(await api.getQuarantine());
      await refreshOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleDeleteQuarantine(id: string) {
    try {
      await api.deleteQuarantine(id);
      setQuarantine(await api.getQuarantine());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleSavePolicy() {
    if (!policyDraft) return;
    try {
      const saved = await api.updatePolicy(policyDraft);
      setPolicyDraft(saved);
      await refreshOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  const openAlerts = alerts.filter((a) => a.status === "open");
  const activeQuarantineCount = quarantine.filter((q) => q.status === "quarantined").length;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-title">
            <Shield size={22} color="#38bdf8" />
            <span>KernLock</span>
          </div>
          <div className="brand-sub">Detect. Block. Explain.</div>
        </div>

        <button className={`nav-btn ${tab === "overview" ? "active" : ""}`} onClick={() => loadTab("overview")}>
          <Activity size={16} /> Overview
        </button>
        <button className={`nav-btn ${tab === "scanner" ? "active" : ""}`} onClick={() => loadTab("scanner")}>
          <FileSearch size={16} /> Scanner & Scripts
        </button>
        <button className={`nav-btn ${tab === "processes" ? "active" : ""}`} onClick={() => loadTab("processes")}>
          <Terminal size={16} /> Processes
        </button>
        <button className={`nav-btn ${tab === "persistence" ? "active" : ""}`} onClick={() => loadTab("persistence")}>
          <Layers size={16} /> Persistence
        </button>
        <button className={`nav-btn ${tab === "alerts" ? "active" : ""}`} onClick={() => loadTab("alerts")}>
          <AlertTriangle size={16} /> Alerts & Events ({openAlerts.length})
        </button>
        <button className={`nav-btn ${tab === "quarantine" ? "active" : ""}`} onClick={() => loadTab("quarantine")}>
          <Archive size={16} /> Quarantine ({activeQuarantineCount})
        </button>
        <button className={`nav-btn ${tab === "policies" ? "active" : ""}`} onClick={() => loadTab("policies")}>
          <Settings size={16} /> Policies & Rules
        </button>
        <button className={`nav-btn ${tab === "reports" ? "active" : ""}`} onClick={() => loadTab("reports")}>
          <FileText size={16} /> Reports
        </button>
      </aside>

      <main className="main">
        <div className="topbar">
          <div>
            <h1 style={{ margin: 0, fontSize: "1.35rem" }}>KernLock Security Console</h1>
            <div style={{ color: "var(--muted)", fontSize: "0.85rem", marginTop: 4 }}>
              {status
                ? `${status.capabilities.hostname} • ${status.capabilities.os}/${status.capabilities.arch} • ${
                    status.capabilities.is_privileged ? "Privileged" : "Unprivileged"
                  }`
                : "Connecting to kernlockd..."}
            </div>
          </div>

          <div className="row">
            {(["audit", "protection", "strict"] as SecurityMode[]).map((m) => (
              <button
                key={m}
                className={`btn ${status?.policy.mode === m ? "" : "btn-secondary"}`}
                onClick={() => handleModeChange(m)}
              >
                <Lock size={13} style={{ marginRight: 5, verticalAlign: -2 }} />
                {m.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {error && <div className="banner banner-error">Error: {error}</div>}

        {status?.capabilities.fallback_reason && (
          <div className="banner banner-warn">
            <strong>Capability Notice:</strong> {status.capabilities.fallback_reason}
          </div>
        )}

        {tab === "overview" && status && (
          <>
            <div className="grid-4">
              <div className="card">
                <div className="metric-label">Effective Mode</div>
                <div className="metric-value">{status.capabilities.active_mode.toUpperCase()}</div>
              </div>
              <div className="card">
                <div className="metric-label">Real-Time File Watcher</div>
                <div className="metric-value">{status.watcher_active ? "ACTIVE" : "IDLE"}</div>
              </div>
              <div className="card">
                <div className="metric-label">Open Threat Alerts</div>
                <div className="metric-value">{openAlerts.length}</div>
              </div>
              <div className="card">
                <div className="metric-label">Quarantined Files</div>
                <div className="metric-value">{activeQuarantineCount}</div>
              </div>
            </div>

            <div className="card">
              <h3>Platform Security Capabilities ({status.capabilities.os})</h3>
              <table className="table">
                <thead>
                  <tr>
                    <th>Subsystem</th>
                    <th>Status</th>
                    <th>Enforcement</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {status.capabilities.capabilities.map((cap) => (
                    <tr key={cap.name}>
                      <td><strong>{cap.name}</strong></td>
                      <td>{cap.active_mode}</td>
                      <td>{cap.enforcement_available ? "Available" : "Audit Only"}</td>
                      <td style={{ color: "var(--muted)" }}>{cap.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="card">
              <h3>Recent Security Events ({events.length})</h3>
              {events.length === 0 ? (
                <p style={{ color: "var(--muted)" }}>No security events recorded yet.</p>
              ) : (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Title</th>
                      <th>Target</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.slice(0, 8).map((ev) => (
                      <tr key={ev.id}>
                        <td><span className={`badge sev-${ev.severity}`}>{ev.severity}</span></td>
                        <td>{ev.title}</td>
                        <td className="mono">{ev.target}</td>
                        <td>{ev.action_taken}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        )}

        {tab === "scanner" && (
          <>
            <div className="card">
              <h3>Static File & Directory Scanner</h3>
              <p style={{ color: "var(--muted)", fontSize: "0.86rem", marginTop: 0 }}>
                Files are hashed, entropy-checked, and matched against structured rules without ever being executed.
              </p>
              <div className="row">
                <input
                  className="input"
                  value={scanPathInput}
                  onChange={(e) => setScanPathInput(e.target.value)}
                  placeholder="/path/to/scan"
                />
                <button className="btn" onClick={handleScanPath} disabled={loading}>
                  {loading ? "Scanning..." : "Scan Path"}
                </button>
              </div>
              {scanResults.length > 0 && (
                <table className="table" style={{ marginTop: 14 }}>
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Path</th>
                      <th>Type & Entropy</th>
                      <th>Explanation</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.map((r) => (
                      <tr key={r.path}>
                        <td><span className={`badge sev-${r.severity}`}>{r.severity} ({r.risk_score})</span></td>
                        <td className="mono">{r.path}</td>
                        <td>
                          <div>{r.file_type}</div>
                          <div style={{ color: "var(--muted)", fontSize: "0.78rem" }}>
                            Entropy: {r.entropy.toFixed(2)} • {r.size_bytes} B
                          </div>
                        </td>
                        <td>{r.summary}</td>
                        <td>
                          {r.is_suspicious && (
                            <button
                              className="btn btn-danger"
                              onClick={() => handleQuarantine(r.path, r.summary)}
                            >
                              Quarantine
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            <div className="card">
              <h3>Command & Script Risk Analyzer</h3>
              <p style={{ color: "var(--muted)", fontSize: "0.86rem", marginTop: 0 }}>
                Paste any shell command or script snippet to inspect its risk indicators safely.
              </p>
              <textarea
                className="textarea"
                value={cmdInput}
                onChange={(e) => setCmdInput(e.target.value)}
                placeholder="e.g. curl -fsSL https://example.com/install.sh | bash"
              />
              <div style={{ marginTop: 10 }}>
                <button className="btn" onClick={handleAnalyzeCmd} disabled={loading}>
                  Analyze Command
                </button>
              </div>
              {cmdResult && (
                <div className="card" style={{ marginTop: 14, background: "var(--surface-alt)" }}>
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <span className={`badge sev-${cmdResult.severity}`}>
                      {cmdResult.severity} • Risk {cmdResult.risk_score}/100
                    </span>
                    <span style={{ color: "var(--muted)", fontSize: "0.82rem" }}>
                      {cmdResult.is_suspicious ? "Suspicious" : "Clean"}
                    </span>
                  </div>
                  <p>{cmdResult.summary}</p>
                  {cmdResult.matches.map((m) => (
                    <div key={m.rule_id} style={{ borderTop: "1px solid var(--border)", paddingTop: 8, marginTop: 8 }}>
                      <strong>[{m.rule_id}] {m.rule_name}</strong>
                      <div style={{ color: "var(--muted)", fontSize: "0.85rem", marginTop: 4 }}>{m.explanation}</div>
                      <div className="mono" style={{ marginTop: 4 }}>Evidence: {m.evidence}</div>
                      <div style={{ color: "#86efac", fontSize: "0.84rem", marginTop: 4 }}>Remediation: {m.remediation}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}

        {tab === "processes" && (
          <div className="card">
            <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
              <h3 style={{ margin: 0 }}>Running Processes ({processes.length})</h3>
              <button className="btn btn-secondary" onClick={() => loadTab("processes")}>Refresh</button>
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>Risk</th>
                  <th>PID / PPID</th>
                  <th>Name</th>
                  <th>Executable</th>
                  <th>Command Line</th>
                </tr>
              </thead>
              <tbody>
                {processes.slice(0, 120).map((p) => (
                  <tr key={p.pid}>
                    <td>
                      <span className={`badge ${p.risk_score >= 40 ? "sev-high" : "sev-info"}`}>
                        {p.risk_score}
                      </span>
                    </td>
                    <td className="mono">{p.pid} / {p.ppid}</td>
                    <td><strong>{p.name}</strong>{p.exe_deleted ? " (deleted exe)" : ""}</td>
                    <td className="mono">{p.exe_path || "-"}</td>
                    <td className="mono">{p.cmdline || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "persistence" && (
          <div className="card">
            <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
              <h3 style={{ margin: 0 }}>Startup & Persistence Entries ({persistence.length})</h3>
              <button className="btn btn-secondary" onClick={() => loadTab("persistence")}>Refresh</button>
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>Risk</th>
                  <th>Source</th>
                  <th>Location</th>
                  <th>Target / Command</th>
                </tr>
              </thead>
              <tbody>
                {persistence.map((entry) => (
                  <tr key={entry.id}>
                    <td>
                      <span className={`badge ${entry.risk_score >= 40 ? "sev-high" : "sev-info"}`}>
                        {entry.risk_score}
                      </span>
                    </td>
                    <td>{entry.source_type}</td>
                    <td className="mono">{entry.location}</td>
                    <td className="mono">{entry.command_or_target}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "alerts" && (
          <>
            <div className="card">
              <h3>Threat Alerts ({alerts.length})</h3>
              <table className="table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Alert</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((a) => (
                    <tr key={a.id}>
                      <td><span className={`badge sev-${a.severity}`}>{a.severity}</span></td>
                      <td>
                        <strong>{a.title}</strong>
                        <div style={{ color: "var(--muted)", fontSize: "0.82rem", marginTop: 4 }}>{a.explanation}</div>
                      </td>
                      <td className="mono">{a.target}</td>
                      <td>{a.status}</td>
                      <td className="row">
                        <button
                          className="btn btn-secondary"
                          onClick={async () => {
                            await api.updateAlertStatus(a.id, "acknowledged");
                            loadTab("alerts");
                          }}
                        >
                          Ack
                        </button>
                        <button
                          className="btn btn-secondary"
                          onClick={async () => {
                            await api.updateAlertStatus(a.id, "resolved");
                            loadTab("alerts");
                          }}
                        >
                          Resolve
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === "quarantine" && (
          <div className="card">
            <h3>Reversible Quarantine Vault ({quarantine.length})</h3>
            <p style={{ color: "var(--muted)", fontSize: "0.86rem", marginTop: 0 }}>
              Quarantined files are stored with non-executable permissions (0600) and SHA-256 integrity verification.
            </p>
            <table className="table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Original Path</th>
                  <th>SHA-256</th>
                  <th>Reason</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {quarantine.map((q) => (
                  <tr key={q.id}>
                    <td><span className="badge sev-medium">{q.status}</span></td>
                    <td className="mono">{q.original_path}</td>
                    <td className="mono">{q.sha256.slice(0, 16)}...</td>
                    <td>{q.reason}</td>
                    <td className="row">
                      {q.status === "quarantined" && (
                        <>
                          <button className="btn" onClick={() => handleRestore(q.id)}>Restore</button>
                          <button className="btn btn-danger" onClick={() => handleDeleteQuarantine(q.id)}>Delete</button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "policies" && policyDraft && (
          <>
            <div className="card">
              <h3>Security Policy & Exclusions</h3>
              <div style={{ display: "grid", gap: 12, maxWidth: 640 }}>
                <div>
                  <label className="metric-label">Auto-Quarantine Risk Threshold (0-100)</label>
                  <input
                    className="input"
                    type="number"
                    value={policyDraft.auto_quarantine_threshold}
                    onChange={(e) =>
                      setPolicyDraft({ ...policyDraft, auto_quarantine_threshold: Number(e.target.value) })
                    }
                  />
                </div>
                <div>
                  <label className="metric-label">Watched Paths</label>
                  <div className="row" style={{ marginTop: 6 }}>
                    <input
                      className="input"
                      value={newWatchPath}
                      onChange={(e) => setNewWatchPath(e.target.value)}
                      placeholder="/home/user/Downloads"
                    />
                    <button
                      className="btn btn-secondary"
                      onClick={() => {
                        if (newWatchPath.trim()) {
                          setPolicyDraft({
                            ...policyDraft,
                            watch_paths: [...policyDraft.watch_paths, newWatchPath.trim()],
                          });
                          setNewWatchPath("");
                        }
                      }}
                    >
                      Add
                    </button>
                  </div>
                  <div className="mono" style={{ marginTop: 6, color: "var(--muted)" }}>
                    {policyDraft.watch_paths.join(", ") || "Default (~/Downloads, /tmp)"}
                  </div>
                </div>
                <div>
                  <label className="metric-label">Excluded Paths</label>
                  <div className="row" style={{ marginTop: 6 }}>
                    <input
                      className="input"
                      value={newExclPath}
                      onChange={(e) => setNewExclPath(e.target.value)}
                      placeholder="/path/to/exclude"
                    />
                    <button
                      className="btn btn-secondary"
                      onClick={() => {
                        if (newExclPath.trim()) {
                          setPolicyDraft({
                            ...policyDraft,
                            excluded_paths: [...policyDraft.excluded_paths, newExclPath.trim()],
                          });
                          setNewExclPath("");
                        }
                      }}
                    >
                      Add
                    </button>
                  </div>
                  <div className="mono" style={{ marginTop: 6, color: "var(--muted)" }}>
                    {policyDraft.excluded_paths.join(", ") || "None"}
                  </div>
                </div>
                <div>
                  <button className="btn" onClick={handleSavePolicy}>Save Policy</button>
                </div>
              </div>
            </div>

            <div className="card">
              <h3>Loaded Detection Rules ({rules.length})</h3>
              <table className="table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Target</th>
                    <th>Name & Explanation</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.id}>
                      <td className="mono">{r.id}</td>
                      <td><span className={`badge sev-${r.severity}`}>{r.severity}</span></td>
                      <td>{r.target}</td>
                      <td>
                        <strong>{r.name}</strong>
                        <div style={{ color: "var(--muted)", fontSize: "0.82rem" }}>{r.explanation}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === "reports" && report && (
          <div className="card">
            <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
              <h3 style={{ margin: 0 }}>Security Report</h3>
              <button
                className="btn"
                onClick={() => {
                  const blob = new Blob([reportMd], { type: "text/markdown" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = "kernlock-security-report.md";
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                Export Markdown
              </button>
            </div>
            <pre className="mono" style={{ whiteSpace: "pre-wrap", background: "var(--bg)", padding: 14, borderRadius: 8 }}>
              {reportMd}
            </pre>
          </div>
        )}
      </main>
    </div>
  );
}
