import type { Classification, Severity } from "../api/types";

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 && i ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function dt(v: string | null | undefined): string {
  if (!v) return "—";
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleString();
}

export function time(v: string | null | undefined): string {
  if (!v) return "—";
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleTimeString(undefined, { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

export function pct(v: number | null | undefined): string {
  return v === null || v === undefined ? "—" : `${Math.round(v * 100)}%`;
}

export function ms(v: number | null | undefined): string {
  if (!v && v !== 0) return "—";
  return v < 1000 ? `${v} ms` : `${(v / 1000).toFixed(1)} s`;
}

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEV_COLOR: Record<Severity, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#facc15",
  low: "#60a5fa",
  info: "#94a3b8",
};

export const SEV_CLASS: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
  low: "bg-sev-low/15 text-sev-low border-sev-low/40",
  info: "bg-sev-info/10 text-sev-info border-sev-info/30",
};

export const CLASS_META: Record<Classification, { label: string; cls: string; color: string }> = {
  UNKNOWN: { label: "Unknown", cls: "text-sev-info border-sev-info/40 bg-sev-info/10", color: "#94a3b8" },
  BENIGN_INDICATORS: { label: "Benign indicators", cls: "text-ok border-ok/40 bg-ok/10", color: "#34d399" },
  SUSPICIOUS: { label: "Suspicious", cls: "text-sev-medium border-sev-medium/40 bg-sev-medium/10", color: "#facc15" },
  HIGHLY_SUSPICIOUS: { label: "Highly suspicious", cls: "text-sev-high border-sev-high/40 bg-sev-high/10", color: "#fb923c" },
  MALICIOUS_INDICATORS: { label: "Malicious indicators", cls: "text-sev-critical border-sev-critical/50 bg-sev-critical/10", color: "#f43f5e" },
};

export const CATEGORY_LABEL: Record<string, string> = {
  structure: "File structure", packing: "Packing / obfuscation", execution: "Execution", persistence: "Persistence",
  injection: "Process injection", credential_access: "Credential access", network: "Network", anti_analysis: "Anti-analysis",
  defense_evasion: "Defense evasion", discovery: "Discovery", collection: "Collection", impact: "Impact", privilege: "Privilege",
  document: "Document threats", archive: "Archive threats", mobile: "Mobile", signature: "Signature", yara: "YARA", ioc: "Indicators",
  vulnerability: "Vulnerabilities", secret: "Secrets", code: "Code weaknesses", file_manipulation: "File manipulation", info: "Info",
};

export function riskColor(score: number | null | undefined): string {
  const s = score ?? 0;
  if (s >= 80) return "#f43f5e";
  if (s >= 60) return "#fb923c";
  if (s >= 35) return "#facc15";
  if (s >= 15) return "#60a5fa";
  return "#34d399";
}

export const RUNNING = new Set(["QUEUED", "VALIDATING", "EXTRACTING", "ANALYZING", "CORRELATING", "REPORTING"]);
export const STAGES = ["QUEUED", "VALIDATING", "EXTRACTING", "ANALYZING", "CORRELATING", "REPORTING", "COMPLETED"];

export function download(url: string) {
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  a.download = "";
  document.body.appendChild(a);
  a.click();
  a.remove();
}
