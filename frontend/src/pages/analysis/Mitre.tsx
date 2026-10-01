import { ExternalLink, Shield } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import type { MitreTechnique } from "../../api/types";
import { Bar, Card, cx, Empty, KV, Spinner } from "../../components/ui";
import { pct } from "../../lib/format";
import { useAsync } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

export default function MitrePage() {
  const { a, completed } = useAnalysis();
  const { data, loading } = useAsync(() => (completed ? api.mitre(a.id) : Promise.resolve(null)), [a.id, completed]);
  const [sel, setSel] = useState<MitreTechnique | null>(null);
  if (!completed) return <NotReady />;
  if (loading && !data) return <Spinner />;
  const techs = data?.techniques || [];
  if (!techs.length) return <Empty icon={<Shield className="h-6 w-6" />}>No ATT&CK technique mapped. MALX only maps a technique when a rule with supporting evidence references it.</Empty>;
  const tactics = (data?.tactics || []).filter((t) => techs.some((x) => x.tactics.includes(t)));
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
      <div className="overflow-x-auto">
        <div className="flex min-w-max gap-3">
          {tactics.map((t) => (
            <div key={t} className="w-56 shrink-0">
              <div className="mb-2 rounded-lg border border-line bg-panel2 px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-accent2">{t.replace(/-/g, " ")}</div>
              <div className="space-y-2">
                {techs.filter((x) => x.tactics.includes(t)).map((x) => (
                  <button key={x.technique_id} type="button" onClick={() => setSel(x)}
                    className={cx("w-full rounded-lg border bg-panel p-2.5 text-left transition hover:border-accent2/60", sel?.technique_id === x.technique_id ? "border-accent2" : "border-line")}>
                    <div className="font-mono text-[11px] text-accent2">{x.technique_id}</div>
                    <div className="text-[12.5px] font-medium leading-snug">{x.name}</div>
                    <div className="mt-1.5 flex items-center gap-2"><Bar value={x.confidence * 100} color="#c084fc" /><span className="text-[11px] text-muted">{pct(x.confidence)}</span></div>
                    <div className="mt-1 text-[11px] text-dim">{x.evidence.length} evidence · {x.findings.length} finding(s)</div>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
      <Card title="Technique detail" className="self-start">
        {!sel ? <div className="text-[13px] text-muted">Select a technique. Each mapping shows its evidence, reason, confidence and source rules.</div> : (
          <div className="space-y-3">
            <div><div className="font-mono text-accent2">{sel.technique_id}</div><div className="text-[15px] font-semibold">{sel.name}</div></div>
            <KV rows={[
              ["Tactics", sel.tactics.join(", ")], ["Confidence", pct(sel.confidence)], ["Reason", sel.reason],
              ["Evidence", <div className="flex flex-wrap gap-1">{sel.evidence.map((e) => <Link key={e} to={`../evidence#${e}`} className="font-mono text-[12px] text-accent">{e}</Link>)}</div>],
              ["Findings", <div className="flex flex-wrap gap-1">{sel.findings.map((f) => <Link key={f} to={`../findings#${f}`} className="font-mono text-[12px] text-accent">{f}</Link>)}{!sel.findings.length && "—"}</div>],
              ["Source", <span className="font-mono text-[12px]">{sel.sources.join(", ")}</span>],
            ]} />
            <a href={sel.url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-[12px] text-accent hover:underline">
              attack.mitre.org <ExternalLink className="h-3 w-3" /></a>
            <p className="text-[11px] text-dim">External link opens only when you click it; MALX never contacts it.</p>
          </div>
        )}
      </Card>
    </div>
  );
}
