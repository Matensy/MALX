import { AlertTriangle, ArrowRight, Brain, FileWarning, Layers, Microscope } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import type { ArtifactBrief, ChainStage, Severity } from "../../api/types";
import { Badge, Bar, Card, ClassBadge, cx, Empty, SeverityBadge } from "../../components/ui";
import { bytes, CATEGORY_LABEL, SEV_COLOR, SEVERITIES } from "../../lib/format";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

function ArtifactTree({ items }: { items: ArtifactBrief[] }) {
  const children = (pid: string | null) => items.filter((x) => x.parent_id === pid);
  const render = (x: ArtifactBrief) => (
    <li key={x.id}>
      <div className="flex items-center gap-2 py-1 text-[13px]">
        <Layers className="h-3.5 w-3.5 shrink-0 text-dim" />
        <Link to={`static?artifact=${x.id}`} className="truncate font-mono hover:text-accent">{x.path_in_archive || x.name}</Link>
        <span className="truncate text-[11px] text-muted">{x.type_label}</span>
        <span className="text-[11px] text-dim">{bytes(x.size)}</span>
        {x.extension_mismatch && <Badge tone="warn"><AlertTriangle className="h-3 w-3" /> EXTENSION MISMATCH</Badge>}
        {x.tags.includes("packed") && <Badge tone="warn">packed</Badge>}
      </div>
      {children(x.id).length > 0 && <ul className="ml-4 border-l border-line pl-3">{children(x.id).map(render)}</ul>}
    </li>
  );
  return <ul>{children(null).map(render)}</ul>;
}

function Chain({ chain, onSelect, selected }: { chain: ChainStage[]; onSelect: (s: ChainStage) => void; selected: string | null }) {
  return (
    <div className="flex flex-wrap items-stretch gap-2">
      {chain.map((c, i) => (
        <div key={c.stage} className="flex items-center gap-2">
          <button type="button" onClick={() => onSelect(c)}
            className={cx("min-w-[118px] rounded-xl border px-4 py-3 text-left transition",
              selected === c.stage ? "border-accent/60 bg-accent/10" : "border-line bg-panel2 hover:border-line2")}>
            <div className="text-2xl font-bold" style={{ color: i >= 4 ? "#f43f5e" : i >= 2 ? "#fb923c" : undefined }}>{c.count}</div>
            <div className="text-[11px] uppercase tracking-wider text-muted">{c.label}</div>
          </button>
          {i < chain.length - 1 && <ArrowRight className="h-4 w-4 text-dim" />}
        </div>
      ))}
    </div>
  );
}

export default function Overview() {
  const { a, completed } = useAnalysis();
  const [stage, setStage] = useState<ChainStage | null>(null);
  const s = a.summary;
  if (!completed || !s) {
    return (
      <div className="space-y-4">
        <NotReady />
        <Card title="Submitted files"><ArtifactTree items={a.artifacts} /></Card>
      </div>
    );
  }
  const dims = Object.entries(a.risk?.dimensions || {});
  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <div className="space-y-4 xl:col-span-2">
        <Card title={<span className="flex items-center gap-2"><Brain className="h-4 w-4" /> MALX investigation</span>}>
          <div className="space-y-1 font-mono text-[13px] leading-relaxed">
            {s.narrative.map((l, i) => <div key={i} className={i === 0 ? "text-text" : "text-muted"}>{l}</div>)}
          </div>
          {s.main_hypothesis && (
            <Link to={`findings#${s.main_hypothesis.ref}`} className="mt-4 flex items-center gap-3 rounded-xl border border-sev-critical/30 bg-sev-critical/5 p-3 hover:border-sev-critical/60">
              <Microscope className="h-5 w-5 text-sev-critical" />
              <div className="min-w-0">
                <div className="text-[11px] uppercase tracking-wider text-muted">Main hypothesis · {s.main_hypothesis.ref}</div>
                <div className="font-semibold">{s.main_hypothesis.title}</div>
              </div>
              <div className="ml-auto"><ClassBadge value={s.classification} /></div>
            </Link>
          )}
          <p className="mt-3 text-[12px] text-muted">{s.classification_reason}. {a.risk?.note}</p>
        </Card>

        <Card title="Analysis chain — click a stage to reveal its data">
          <Chain chain={s.chain} onSelect={(c) => setStage(stage?.stage === c.stage ? null : c)} selected={stage?.stage || null} />
          {stage && (
            <div className="mt-4 flex flex-wrap gap-1.5">
              {stage.refs.length === 0 && <span className="text-[13px] text-muted">Nothing at this stage.</span>}
              {stage.refs.slice(0, 200).map((r) => (
                <Link key={r} to={r.startsWith("F-") ? `findings#${r}` : `evidence#${r}`}
                  className="rounded-md border border-line2 bg-panel3 px-2 py-0.5 font-mono text-[11px] hover:border-accent/60 hover:text-accent">{r}</Link>
              ))}
            </div>
          )}
        </Card>

        <Card title="Risk model — every score shows its reasons">
          <div className="grid gap-x-8 gap-y-3 md:grid-cols-2">
            {dims.map(([k, d]) => (
              <div key={k}>
                <div className="mb-1 flex justify-between text-[13px]"><span>{d.label}</span><span className="font-semibold">{d.score}</span></div>
                <Bar value={d.score} />
                <div className="mt-1 space-y-0.5">
                  {d.reasons.slice(0, 3).map((r) => (
                    <Link key={r.ref} to={`evidence#${r.ref}`} className="block truncate text-[11px] text-muted hover:text-accent">
                      <span className="font-mono text-dim">{r.ref}</span> {r.title}
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Artifacts"><ArtifactTree items={a.artifacts} /></Card>
      </div>

      <div className="space-y-4">
        <Card title="Findings by severity">
          <div className="space-y-2">
            {SEVERITIES.map((sev) => (
              <Link to={`findings?severity=${sev}`} key={sev} className="grid grid-cols-[90px_1fr_32px] items-center gap-2 text-[13px] hover:opacity-80">
                <SeverityBadge severity={sev as Severity} />
                <Bar value={(a.severity_counts[sev as Severity] / Math.max(1, a.finding_count)) * 100} color={SEV_COLOR[sev as Severity]} />
                <span className="text-right font-semibold">{a.severity_counts[sev as Severity]}</span>
              </Link>
            ))}
          </div>
        </Card>
        <Card title="Capabilities (indicators, not proof)">
          {s.capabilities.length === 0 ? <Empty>No capability indicators.</Empty> : (
            <ul className="space-y-1.5">
              {s.capabilities.map((c) => (
                <li key={c.category} className="flex items-center gap-2 text-[13px]">
                  <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[c.max_severity] }} />
                  <Link to={`evidence?category=${c.category}`} className="flex-1 hover:text-accent">{CATEGORY_LABEL[c.category] || c.label}</Link>
                  <span className="text-[12px] text-muted">{c.count}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Limitations">
          {a.limitations.length === 0 ? <div className="text-[13px] text-muted">None recorded.</div> : (
            <ul className="space-y-1.5 text-[12px] text-muted">
              {a.limitations.map((l, i) => <li key={i} className="flex gap-2"><FileWarning className="mt-0.5 h-3.5 w-3.5 shrink-0" />{l}</li>)}
            </ul>
          )}
          <p className="mt-3 border-t border-line pt-3 text-[12px] text-dim">Static analysis only — the sample was never executed. Runtime-only behaviour is not observed.</p>
        </Card>
        <Card title="Engines">
          <ul className="space-y-1 text-[12px]">
            {Object.entries(a.engines || {}).filter(([k]) => !["worker_hardening", "engine_version"].includes(k)).map(([k, v]: [string, any]) => (
              <li key={k} className="flex justify-between gap-2"><span className="text-muted">{k}</span>
                <span className={v?.status === "ok" ? "text-ok" : "text-sev-medium"}>{v?.status}{v?.version ? ` · ${v.version}` : ""}</span></li>
            ))}
            {a.engines?.worker_hardening && (
              <li className="pt-2 text-[11px] text-dim">Worker: {Object.entries(a.engines.worker_hardening).map(([k, v]) => `${k}=${v}`).join(", ")}</li>
            )}
          </ul>
        </Card>
      </div>
    </div>
  );
}
