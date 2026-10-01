import type {
  AnalysisDetail, AnalysisSummary, ArtifactBrief, ArtifactDetail, Board, Evidence, Finding, GraphData, IOC,
  MitreTechnique, ReverseFunction, SystemInfo, TimelineEvent,
} from "./types";

const BASE = "/api";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method || "GET").toUpperCase();
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
  // Required by the backend for every state-changing request (CSRF protection).
  if (method !== "GET") headers["X-MALX-Request"] = "1";
  if (init.body && typeof init.body === "string") headers["Content-Type"] = "application/json";
  const res = await fetch(BASE + path, { ...init, headers, credentials: "same-origin" });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const j = await res.json();
      detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  const ct = res.headers.get("content-type") || "";
  return (ct.includes("application/json") ? res.json() : res.text()) as Promise<T>;
}

const q = (params: Record<string, string | number | boolean | undefined | null>) => {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") u.set(k, String(v));
  const s = u.toString();
  return s ? `?${s}` : "";
};

export const api = {
  system: () => req<SystemInfo>("/system"),
  stats: () => req<any>("/stats"),
  rules: () => req<any>("/rules"),
  list: (params: { limit?: number; offset?: number; q?: string } = {}) =>
    req<{ total: number; items: AnalysisSummary[] }>(`/analyses${q(params)}`),
  get: (id: string) => req<AnalysisDetail>(`/analyses/${id}`),
  remove: (id: string) => req<any>(`/analyses/${id}`, { method: "DELETE" }),
  cancel: (id: string) => req<any>(`/analyses/${id}/cancel`, { method: "POST" }),
  reanalyze: (id: string) => req<any>(`/analyses/${id}/reanalyze`, { method: "POST" }),
  artifacts: (id: string) => req<ArtifactBrief[]>(`/analyses/${id}/artifacts`),
  artifact: (id: string, aid: string) => req<ArtifactDetail>(`/analyses/${id}/artifacts/${aid}`),
  strings: (id: string, aid: string, p: { classification?: string; q?: string; offset?: number; limit?: number }) =>
    req<{ total: number; counts: Record<string, number>; items: any[] }>(`/analyses/${id}/artifacts/${aid}/strings${q(p)}`),
  hex: (id: string, aid: string, offset: number, length = 512) =>
    req<{ offset: number; length: number; size: number; hex: string }>(`/analyses/${id}/artifacts/${aid}/hex${q({ offset, length })}`),
  functions: (id: string, aid: string) => req<any>(`/analyses/${id}/artifacts/${aid}/functions`),
  fn: (id: string, aid: string, addr: string) => req<ReverseFunction>(`/analyses/${id}/artifacts/${aid}/functions/${encodeURIComponent(addr)}`),
  findings: (id: string) => req<Finding[]>(`/analyses/${id}/findings`),
  chain: (id: string, ref: string) => req<any>(`/analyses/${id}/findings/${ref}/chain`),
  patchFinding: (id: string, ref: string, body: { status?: string; note?: string }) =>
    req<any>(`/analyses/${id}/findings/${ref}`, { method: "PATCH", body: JSON.stringify(body) }),
  createFinding: (id: string, body: { title: string; severity: string; what?: string; why?: string; evidence: string[]; status?: string }) =>
    req<{ id: string }>(`/analyses/${id}/findings`, { method: "POST", body: JSON.stringify(body) }),
  evidence: (id: string) => req<Evidence[]>(`/analyses/${id}/evidence`),
  patchEvidence: (id: string, ref: string, body: { status?: string; note?: string }) =>
    req<any>(`/analyses/${id}/evidence/${ref}`, { method: "PATCH", body: JSON.stringify(body) }),
  iocs: (id: string) => req<IOC[]>(`/analyses/${id}/iocs`),
  globalIocs: (p: { q?: string; include_common?: boolean } = {}) => req<IOC[]>(`/iocs${q(p)}`),
  graph: (id: string, includeWeak = false) => req<GraphData>(`/analyses/${id}/graph${q({ include_weak: includeWeak })}`),
  timeline: (id: string) => req<TimelineEvent[]>(`/analyses/${id}/timeline`),
  mitre: (id: string) => req<{ techniques: MitreTechnique[]; tactics: string[] }>(`/analyses/${id}/mitre`),
  yara: (id: string) => req<any[]>(`/analyses/${id}/yara`),
  appsec: (id: string) => req<any>(`/analyses/${id}/appsec`),
  board: (id: string) => req<Board>(`/analyses/${id}/board`),
  saveBoard: (id: string, b: Board) => req<any>(`/analyses/${id}/board`, { method: "PUT", body: JSON.stringify(b) }),
  search: (term: string) => req<Record<string, any[]>>(`/search${q({ q: term })}`),
};

export const urls = {
  report: (id: string, format: string, download = false) => `${BASE}/analyses/${id}/report${q({ format, download: download || undefined })}`,
  iocs: (id: string, format: string, defang = false) => `${BASE}/analyses/${id}/iocs${q({ format, defang: defang || undefined })}`,
  globalIocs: (format: string, defang = false) => `${BASE}/iocs${q({ format, defang: defang || undefined })}`,
  export: (id: string, kind: string) => `${BASE}/analyses/${id}/export/${kind}`,
};

export function uploadAnalysis(
  files: File[],
  fields: { mode: string; password?: string; notes?: string; name?: string },
  onProgress: (pct: number) => void,
): Promise<{ id: string }> {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    for (const f of files) form.append("files", f, f.name);
    form.append("mode", fields.mode);
    if (fields.password) form.append("password", fields.password);
    if (fields.notes) form.append("notes", fields.notes);
    if (fields.name) form.append("name", fields.name);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${BASE}/analyses`);
    xhr.setRequestHeader("X-MALX-Request", "1");
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(JSON.parse(xhr.responseText));
      else {
        let msg = xhr.statusText;
        try {
          msg = JSON.parse(xhr.responseText).detail;
        } catch {
          /* ignore */
        }
        reject(new ApiError(xhr.status, msg));
      }
    };
    xhr.onerror = () => reject(new ApiError(0, "network error"));
    xhr.send(form);
  });
}
