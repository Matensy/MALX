import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { Badge, Card, cx, Empty, Spinner, Tabs } from "../../components/ui";
import { dt, time } from "../../lib/format";
import { useAsync } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

export default function TimelinePage() {
  const { a, completed } = useAnalysis();
  const { data, loading } = useAsync(() => (completed ? api.timeline(a.id) : Promise.resolve([])), [a.id, completed]);
  const [lane, setLane] = useState<"pipeline" | "artifact">("pipeline");
  const names = useMemo(() => Object.fromEntries(a.artifacts.map((x) => [x.id, x.name])), [a.artifacts]);
  if (!completed) return <NotReady />;
  if (loading && !data) return <Spinner />;
  const items = (data || []).filter((t) => t.lane === lane);
  return (
    <div className="space-y-4">
      <Tabs value={lane} onChange={setLane} tabs={[
        { id: "pipeline", label: "Analysis timeline", count: (data || []).filter((t) => t.lane === "pipeline").length },
        { id: "artifact", label: "Artifact timestamps", count: (data || []).filter((t) => t.lane === "artifact").length },
      ]} />
      <Card>
        <p className="mb-4 text-[12px] text-muted">{lane === "pipeline" ? "Every engine step with a timestamp — the reproducible chain of the investigation." :
          "Timestamps embedded in the samples (compile time, archive members, document metadata, certificates). They can be forged."}</p>
        {items.length === 0 ? <Empty>No events.</Empty> : (
          <ol className="relative ml-3 border-l border-line2">
            {items.map((t, i) => (
              <li key={i} className="mb-3 ml-5">
                <span className={cx("absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full border",
                  t.event.startsWith("YARA") || t.event.startsWith("Heuristic") ? "border-sev-high bg-sev-high/60" : t.event.startsWith("Classification") ? "border-sev-critical bg-sev-critical" : "border-accent bg-accent/40")} />
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-mono text-[12px] text-accent">{lane === "pipeline" ? time(t.ts) : dt(t.ts)}</span>
                  <span className="text-[13px]">{t.event}</span>
                  {t.engine && <Badge>{t.engine}</Badge>}
                  {t.artifact_id && names[t.artifact_id] && <Link to={`../static?artifact=${t.artifact_id}`} className="font-mono text-[11px] text-muted hover:text-accent">{names[t.artifact_id]}</Link>}
                  {t.evidence_ref && <Link to={`../evidence#${t.evidence_ref}`} className="font-mono text-[11px] text-accent">{t.evidence_ref}</Link>}
                </div>
                {t.detail && <div className="truncate font-mono text-[11px] text-dim">{t.detail}</div>}
              </li>
            ))}
          </ol>
        )}
      </Card>
    </div>
  );
}
