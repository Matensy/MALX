import { ArrowRight, GitBranch, ListTree, Network } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import type { AnalystState, Finding, Severity } from "../../api/types";
import { Badge, Button, Card, cx, Empty, Select, SeverityBadge, Spinner } from "../../components/ui";
import { pct, SEV_COLOR, SEVERITIES } from "../../lib/format";
import { useAsync } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

const STATES: AnalystState[] = ["UNKNOWN", "INVESTIGATING", "SUPPORTED", "CONFIRMED", "DISMISSED"];

function ChainView({ aid, ref_ }: { aid: string; ref_: string }) {
  const { data } = useAsync(() => api.chain(aid, ref_), [aid, ref_]);
  if (!data) return <Spinner />;
  return (
    <div className="flex flex-wrap items-stretch gap-2">
      {data.stages.map((s: any, i: number) => (
        <div key={s.stage} className="flex items-center gap-2">
          <div className="min-w-[140px] max-w-[260px] rounded-lg border border-line bg-panel3 p-2">
            <div className="text-[10.5px] font-bold uppercase tracking-wider text-accent">{s.stage}</div>
            <ul className="mt-1 space-y-0.5 text-[11.5px]">
              {s.items.slice(0, 6).map((it: any, k: number) => (
                <li key={k} className="truncate">
                  {typeof it === "string" ? it : (
                    <Link to={it.id?.startsWith("F-") ? `#${it.id}` : `../evidence#${it.id}`} className="hover:text-accent">
                      <span className="font-mono text-dim">{it.id}</span> {it.title}
                    </Link>
                  )}
                </li>
              ))}
              {s.items.length > 6 && <li className="text-dim">+{s.items.length - 6} more</li>}
              {s.items.length === 0 && <li className="text-dim">—</li>}
            </ul>
          </div>
          {i < data.stages.length - 1 && <ArrowRight className="h-4 w-4 shrink-0 text-dim" />}
        </div>
      ))}
    </div>
  );
}

function FindingCard({ f, aid, open, onToggle, onUpdate }: { f: Finding; aid: string; open: boolean; onToggle: () => void; onUpdate: (f: Finding) => void }) {
  const [chain, setChain] = useState(false);
  return (
    <div id={f.id} className={cx("rounded-xl border bg-panel transition", open ? "border-line2" : "border-line")} style={{ borderLeft: `3px solid ${SEV_COLOR[f.severity]}` }}>
      <button type="button" onClick={onToggle} className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left">
        <SeverityBadge severity={f.severity} />
        <span className="font-mono text-[12px] text-dim">{f.id}</span>
        <span className="min-w-0 flex-1 font-semibold">{f.title}</span>
        <Badge tone={f.strength === "strong" ? "danger" : f.strength === "moderate" ? "warn" : "default"}>{f.strength}</Badge>
        <Badge>{f.kind}</Badge>
        {f.needs_review && <Badge tone="accent">manual review</Badge>}
        <span className="w-12 text-right text-[13px] font-semibold">{pct(f.confidence)}</span>
      </button>
      {open && (
        <div className="space-y-4 border-t border-line px-4 py-4">
          <dl className="grid gap-x-6 gap-y-3 text-[13px] md:grid-cols-[110px_1fr]">
            <dt className="font-semibold text-muted">What?</dt><dd>{f.what}</dd>
            <dt className="font-semibold text-muted">Where?</dt>
            <dd className="flex flex-wrap gap-1">{f.where.length ? f.where.map((w) => <code key={w} className="rounded bg-panel3 px-1.5 py-0.5 text-[12px]">{w}</code>) : "analysis"}</dd>
            <dt className="font-semibold text-muted">Why?</dt><dd>{f.why}</dd>
            <dt className="font-semibold text-muted">Evidence?</dt>
            <dd>
              <ul className="space-y-1">
                {f.evidence.map((e) => (
                  <li key={e.id} className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={e.severity} />
                    <Link to={`../evidence#${e.id}`} className="font-mono text-[12px] text-accent hover:underline">{e.id}</Link>
                    <span>{e.title}</span>
                    <span className="text-[11px] text-dim">{e.role} · {e.source_label} · {pct(e.confidence)}</span>
                  </li>
                ))}
              </ul>
            </dd>
            <dt className="font-semibold text-muted">Confidence?</dt>
            <dd>{pct(f.confidence)} — {f.strength} support from {f.sources.join(", ") || "—"}{f.needs_review ? "; requires manual review" : ""}</dd>
            <dt className="font-semibold text-muted">Limitations?</dt>
            <dd><ul className="space-y-0.5 text-muted">{f.limitations.map((l, i) => <li key={i}>• {l}</li>)}</ul></dd>
            {f.mitre.length > 0 && (<><dt className="font-semibold text-muted">MITRE</dt><dd className="flex flex-wrap gap-1">{f.mitre.map((t) => <Link key={t} to="../mitre"><Badge tone="accent">{t}</Badge></Link>)}</dd></>)}
            {f.cwe && (<><dt className="font-semibold text-muted">CWE</dt><dd><Badge>{f.cwe}</Badge></dd></>)}
            {f.recommendation && (<><dt className="font-semibold text-muted">Action</dt><dd>{f.recommendation}</dd></>)}
          </dl>
          <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
            <Link to={`../evidence?finding=${f.id}`}><Button><ListTree className="h-4 w-4" /> View evidence</Button></Link>
            <Link to={`../graph?focus=${f.id}`}><Button><Network className="h-4 w-4" /> View graph</Button></Link>
            <Button onClick={() => setChain(!chain)}><GitBranch className="h-4 w-4" /> Chain of analysis</Button>
            <div className="ml-auto flex items-center gap-2 text-[12px] text-muted">
              Analyst state
              <Select value={f.status} onChange={async (v) => { await api.patchFinding(aid, f.id, { status: v }); onUpdate({ ...f, status: v as AnalystState }); }}
                options={STATES.map((s) => ({ value: s, label: s }))} />
            </div>
          </div>
          {chain && <ChainView aid={aid} ref_={f.id} />}
        </div>
      )}
    </div>
  );
}

export default function FindingsPage() {
  const { a, completed } = useAnalysis();
  const loc = useLocation();
  const [params, setParams] = useSearchParams();
  const { data, setData, loading } = useAsync(() => (completed ? api.findings(a.id) : Promise.resolve([])), [a.id, completed]);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [kind, setKind] = useState("all");
  const sev = params.get("severity") as Severity | null;
  useEffect(() => {
    const ref = loc.hash.replace("#", "");
    if (ref) {
      setOpen((o) => new Set(o).add(ref));
      setTimeout(() => document.getElementById(ref)?.scrollIntoView({ behavior: "smooth", block: "start" }), 150);
    } else if (data?.length) setOpen((o) => (o.size ? o : new Set([data[0].id])));
  }, [loc.hash, data]);
  const filtered = useMemo(() => (data || []).filter((f) => (!sev || f.severity === sev) && (kind === "all" || f.kind === kind)), [data, sev, kind]);
  if (!completed) return <NotReady />;
  if (loading && !data) return <Spinner />;
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, (data || []).filter((f) => f.severity === s).length]));
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        {SEVERITIES.map((s) => (
          <button key={s} type="button" onClick={() => setParams(sev === s ? {} : { severity: s })}
            className={cx("rounded-xl border bg-panel p-3 text-left transition", sev === s ? "border-line2 ring-1 ring-accent/40" : "border-line hover:border-line2")}>
            <div className="text-[11px] font-bold uppercase tracking-wider" style={{ color: SEV_COLOR[s] }}>{s}</div>
            <div className="text-2xl font-bold">{counts[s]}</div>
          </button>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Select value={kind} onChange={setKind} options={[{ value: "all", label: "All kinds" }, { value: "correlated", label: "Correlated" },
          { value: "indicator", label: "Single/weak indicators" }, { value: "appsec", label: "Application security" }, { value: "analyst", label: "Analyst" }]} />
        <span className="text-[12px] text-muted">{filtered.length} finding(s) · correlated findings combine evidence from several engines; indicators need review.</span>
        <Button variant="ghost" className="ml-auto" onClick={() => setOpen(new Set(filtered.map((f) => f.id)))}>Expand all</Button>
      </div>
      {filtered.length === 0 ? <Empty>No findings{sev ? ` with severity ${sev}` : ""}.</Empty> : (
        <div className="space-y-2">
          {filtered.map((f) => (
            <FindingCard key={f.id} f={f} aid={a.id} open={open.has(f.id)}
              onToggle={() => setOpen((o) => { const n = new Set(o); n.has(f.id) ? n.delete(f.id) : n.add(f.id); return n; })}
              onUpdate={(nf) => setData((data || []).map((x) => (x.id === nf.id ? nf : x)))} />
          ))}
        </div>
      )}
      <Card><p className="text-[12px] text-muted">Every finding answers What / Where / Why / Evidence / Confidence / Limitations. A technique can be legitimate in legitimate software — conclusions come from combined evidence, never from a single observation.</p></Card>
    </div>
  );
}
