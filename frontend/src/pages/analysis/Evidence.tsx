import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import type { AnalystState, Evidence } from "../../api/types";
import JsonTree from "../../components/JsonTree";
import { Badge, Button, Card, cx, Empty, Input, Select, SeverityBadge, Spinner } from "../../components/ui";
import { CATEGORY_LABEL, pct, SEV_COLOR, SEVERITIES } from "../../lib/format";
import { useAsync } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

const STATES: AnalystState[] = ["UNKNOWN", "INVESTIGATING", "SUPPORTED", "CONFIRMED", "DISMISSED"];

function EvidenceCard({ e, aid, open, onToggle, onUpdate }: { e: Evidence; aid: string; open: boolean; onToggle: () => void; onUpdate: (e: Evidence) => void }) {
  const [note, setNote] = useState(e.analyst_note || "");
  return (
    <div id={e.id} className={cx("rounded-lg border bg-panel", open ? "border-line2" : "border-line", e.analyst_state === "DISMISSED" && "opacity-50")}
      style={{ borderLeft: `3px solid ${SEV_COLOR[e.severity]}` }}>
      <button type="button" onClick={onToggle} className="flex w-full flex-wrap items-center gap-2 px-3 py-2 text-left">
        <SeverityBadge severity={e.severity} />
        <span className="font-mono text-[12px] text-dim">{e.id}</span>
        <span className="min-w-0 flex-1 truncate text-[13px]">{e.title}</span>
        <Badge>{e.source_label}</Badge>
        <span className="hidden text-[11px] text-muted md:inline">{CATEGORY_LABEL[e.category] || e.category}</span>
        {e.related_findings.map((f) => <Badge key={f} tone="accent">{f}</Badge>)}
        {e.analyst_state !== "UNKNOWN" && <Badge tone={e.analyst_state === "CONFIRMED" ? "danger" : "default"}>{e.analyst_state}</Badge>}
        <span className="w-10 text-right text-[12px] text-muted">{pct(e.confidence)}</span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-line px-3 py-3 text-[13px]">
          <p>{e.description}</p>
          <div className="grid gap-x-6 gap-y-1 text-[12px] md:grid-cols-3">
            <div><span className="text-muted">Type</span> <code>{e.type}</code></div>
            <div><span className="text-muted">Artifact</span> {e.artifact || "—"}</div>
            <div><span className="text-muted">Reliability</span> {e.reliability}</div>
            <div><span className="text-muted">Rule</span> <code>{e.rule_id || "—"}</code></div>
            <div><span className="text-muted">Offset</span> {e.offset !== null ? <code>0x{e.offset.toString(16)}</code> : "—"}</div>
            <div><span className="text-muted">MITRE</span> {e.mitre.join(", ") || "—"}</div>
          </div>
          {e.value && <pre className="max-h-40 overflow-auto whitespace-pre-wrap rounded border border-line bg-bg p-2 font-mono text-[12px] break-any">{e.value}</pre>}
          {e.details && Object.keys(e.details).length > 0 && <JsonTree value={e.details} name="details" />}
          {e.related_findings.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-[12px]"><span className="text-muted">Supports</span>
              {e.related_findings.map((f) => <Link key={f} to={`../findings#${f}`} className="font-mono text-accent hover:underline">{f}</Link>)}</div>
          )}
          <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
            <span className="text-[12px] text-muted">Analyst state</span>
            <Select value={e.analyst_state} options={STATES.map((s) => ({ value: s, label: s }))}
              onChange={async (v) => { await api.patchEvidence(aid, e.id, { status: v }); onUpdate({ ...e, analyst_state: v as AnalystState }); }} />
            <Input value={note} onChange={(ev) => setNote(ev.target.value)} placeholder="Analyst note" className="min-w-[200px] flex-1" />
            <Button onClick={async () => { await api.patchEvidence(aid, e.id, { note }); onUpdate({ ...e, analyst_note: note }); }}>Save note</Button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function EvidencePage() {
  const { a, completed } = useAnalysis();
  const loc = useLocation();
  const [params] = useSearchParams();
  const { data, setData, loading } = useAsync(() => (completed ? api.evidence(a.id) : Promise.resolve([])), [a.id, completed]);
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [cat, setCat] = useState(params.get("category") || "");
  const [src, setSrc] = useState("");
  const [hideInfo, setHideInfo] = useState(true);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const finding = params.get("finding");
  useEffect(() => {
    const ref = loc.hash.replace("#", "");
    if (ref) {
      setHideInfo(false);
      setOpen((o) => new Set(o).add(ref));
      setTimeout(() => document.getElementById(ref)?.scrollIntoView({ behavior: "smooth", block: "center" }), 200);
    }
  }, [loc.hash, data]);
  const sources = useMemo(() => [...new Set((data || []).map((e) => e.source_label))].sort(), [data]);
  const cats = useMemo(() => [...new Set((data || []).map((e) => e.category))].sort(), [data]);
  const list = (data || []).filter((e) =>
    (!finding || e.related_findings.includes(finding)) && (!sev || e.severity === sev) && (!cat || e.category === cat) && (!src || e.source_label === src) &&
    (!hideInfo || e.severity !== "info" || e.related_findings.length > 0 || loc.hash === `#${e.id}`) &&
    (!q || `${e.title} ${e.value} ${e.type} ${e.rule_id}`.toLowerCase().includes(q.toLowerCase())));
  if (!completed) return <NotReady />;
  if (loading && !data) return <Spinner />;
  return (
    <div className="space-y-3">
      <Card pad>
        <div className="flex flex-wrap items-center gap-2">
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search evidence (title, value, rule)" className="w-72" />
          <Select value={sev} onChange={setSev} options={[{ value: "", label: "All severities" }, ...SEVERITIES.map((s) => ({ value: s, label: s }))]} />
          <Select value={cat} onChange={setCat} options={[{ value: "", label: "All categories" }, ...cats.map((c) => ({ value: c, label: CATEGORY_LABEL[c] || c }))]} />
          <Select value={src} onChange={setSrc} options={[{ value: "", label: "All engines" }, ...sources.map((s) => ({ value: s, label: s }))]} />
          <label className="flex items-center gap-1.5 text-[12px] text-muted"><input type="checkbox" checked={hideInfo} onChange={(e) => setHideInfo(e.target.checked)} /> hide unlinked info</label>
          {finding && <Badge tone="accent">supporting {finding} <Link to="." className="ml-1">✕</Link></Badge>}
          <span className="ml-auto text-[12px] text-muted">{list.length} / {data?.length ?? 0} observations</span>
        </div>
      </Card>
      {list.length === 0 ? <Empty>No evidence matches.</Empty> : (
        <div className="space-y-1.5">
          {list.map((e) => (
            <EvidenceCard key={e.id} e={e} aid={a.id} open={open.has(e.id)}
              onToggle={() => setOpen((o) => { const n = new Set(o); n.has(e.id) ? n.delete(e.id) : n.add(e.id); return n; })}
              onUpdate={(ne) => setData((data || []).map((x) => (x.id === ne.id ? ne : x)))} />
          ))}
        </div>
      )}
    </div>
  );
}
