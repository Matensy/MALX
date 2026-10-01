import { FilePlus2, RefreshCw, Trash2 } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { AnalysisSummary, Classification } from "../api/types";
import { Badge, Bar, Button, Card, ClassBadge, Empty, ErrorBox, Input, Stat } from "../components/ui";
import { CLASS_META, dt, ms, RUNNING, SEV_COLOR, SEVERITIES } from "../lib/format";
import { useAsync, useDebounced, useInterval } from "../lib/hooks";
import { useState } from "react";

function StatusCell({ a }: { a: AnalysisSummary }) {
  if (RUNNING.has(a.status)) {
    return (
      <div className="w-36">
        <div className="mb-1 flex justify-between text-[11px]"><span className="animate-pulse-line text-accent">{a.status}</span><span className="text-muted">{a.progress}%</span></div>
        <Bar value={a.progress} color="#38bdf8" />
      </div>
    );
  }
  const tone = a.status === "COMPLETED" ? "ok" : a.status === "FAILED" ? "danger" : "default";
  return <Badge tone={tone as any} title={a.error || undefined}>{a.status === "COMPLETED" ? "DONE" : a.status}</Badge>;
}

export default function Dashboard() {
  const nav = useNavigate();
  const [filter, setFilter] = useState("");
  const q = useDebounced(filter);
  const list = useAsync(() => api.list({ limit: 100, q }), [q]);
  const stats = useAsync(() => api.stats(), []);
  const running = list.data?.items.some((a) => RUNNING.has(a.status));
  useInterval(() => {
    list.reload();
    stats.reload();
  }, running ? 1500 : null);

  const byClass = stats.data?.by_classification || {};
  const bySev = stats.data?.findings_by_severity || {};
  const totalFindings = SEVERITIES.reduce((n, s) => n + (bySev[s] || 0), 0);

  return (
    <div className="mx-auto max-w-7xl space-y-5 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Investigations</h1>
          <p className="text-[13px] text-muted">Static analysis, reverse engineering and evidence correlation — nothing you upload is ever executed.</p>
        </div>
        <Link to="/analysis/new"><Button variant="primary"><FilePlus2 className="h-4 w-4" /> New analysis</Button></Link>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Analyses" value={stats.data?.analyses ?? "—"} sub={`${stats.data?.by_status?.COMPLETED ?? 0} completed`} />
        <Stat label="Malicious indicators" value={byClass.MALICIOUS_INDICATORS ?? 0} color={CLASS_META.MALICIOUS_INDICATORS.color}
          sub={`${byClass.HIGHLY_SUSPICIOUS ?? 0} highly suspicious`} />
        <Stat label="Findings" value={totalFindings} sub={`${(bySev.critical || 0) + (bySev.high || 0)} high or critical`} />
        <Stat label="Evidence items" value={stats.data?.evidence ?? "—"} sub="structured observations" />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Classification distribution" className="lg:col-span-1">
          <div className="space-y-2.5">
            {(Object.keys(CLASS_META) as Classification[]).map((k) => {
              const n = byClass[k] || 0;
              const max = Math.max(1, ...Object.values(byClass).map(Number));
              return (
                <div key={k} className="grid grid-cols-[150px_1fr_30px] items-center gap-2 text-[12px]">
                  <span className="text-muted">{CLASS_META[k].label}</span>
                  <Bar value={(n / max) * 100} color={CLASS_META[k].color} />
                  <span className="text-right font-semibold">{n}</span>
                </div>
              );
            })}
          </div>
          <div className="mt-4 border-t border-line pt-3">
            <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted">Findings by severity</div>
            <div className="flex h-3 overflow-hidden rounded-full bg-line">
              {SEVERITIES.map((s) => (bySev[s] ? <div key={s} title={`${s}: ${bySev[s]}`} style={{ width: `${(bySev[s] / Math.max(1, totalFindings)) * 100}%`, background: SEV_COLOR[s] }} /> : null))}
            </div>
            <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-muted">
              {SEVERITIES.map((s) => <span key={s} className="flex items-center gap-1"><i className="inline-block h-2 w-2 rounded-full" style={{ background: SEV_COLOR[s] }} />{s} {bySev[s] || 0}</span>)}
            </div>
          </div>
        </Card>

        <Card title="Recent analyses" className="lg:col-span-2" pad={false}
          actions={<>
            <Input placeholder="Filter by name or SHA256" value={filter} onChange={(e) => setFilter(e.target.value)} className="w-64" />
            <Button variant="ghost" onClick={() => list.reload()} title="Refresh"><RefreshCw className="h-4 w-4" /></Button>
          </>}>
          <ErrorBox error={list.error} />
          {list.data && list.data.items.length === 0 ? (
            <div className="p-6"><Empty>No analyses yet. Start with <Link className="text-accent" to="/analysis/new">a new analysis</Link>.</Empty></div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-muted">
                    <th className="px-4 py-2">Sample</th><th className="px-3 py-2">Type</th><th className="px-3 py-2">Verdict</th>
                    <th className="px-3 py-2">Risk</th><th className="px-3 py-2">Findings</th><th className="px-3 py-2">Status</th><th className="px-3 py-2" />
                  </tr>
                </thead>
                <tbody>
                  {list.data?.items.map((a) => (
                    <tr key={a.id} onClick={() => nav(`/analysis/${a.id}`)} className="cursor-pointer border-b border-line/60 hover:bg-panel2">
                      <td className="max-w-[260px] px-4 py-2.5">
                        <div className="truncate font-medium">{a.name}</div>
                        <div className="truncate font-mono text-[11px] text-dim">{a.sha256 || a.id} · {dt(a.created_at)} · {ms(a.duration_ms)}</div>
                      </td>
                      <td className="max-w-[200px] truncate px-3 py-2.5 text-muted">{a.main_type || "—"}</td>
                      <td className="px-3 py-2.5">{a.classification ? <ClassBadge value={a.classification} /> : <span className="text-dim">—</span>}</td>
                      <td className="w-24 px-3 py-2.5">{a.risk_score !== null ? <div className="flex items-center gap-2"><span className="w-7 font-semibold">{a.risk_score}</span><Bar value={a.risk_score} /></div> : "—"}</td>
                      <td className="px-3 py-2.5">{a.finding_count}</td>
                      <td className="px-3 py-2.5"><StatusCell a={a} /></td>
                      <td className="px-3 py-2.5 text-right">
                        <button title="Delete analysis and purge its files" className="text-dim hover:text-sev-critical"
                          onClick={async (e) => {
                            e.stopPropagation();
                            if (confirm(`Delete analysis "${a.name}" and purge all its stored files?`)) {
                              await api.remove(a.id);
                              list.reload();
                              stats.reload();
                            }
                          }}>
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
