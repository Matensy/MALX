import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, ClassBadge, Empty, SeverityBadge, Spinner } from "../components/ui";
import { useAsync } from "../lib/hooks";

const SECTIONS: { key: string; label: string; render: (x: any) => React.ReactNode; to: (x: any) => string }[] = [
  { key: "analyses", label: "Analyses", render: (x) => <><span className="font-medium">{x.name}</span> {x.classification && <ClassBadge value={x.classification} />} <code className="text-[11px] text-dim">{x.sha256}</code></>, to: (x) => `/analysis/${x.id}` },
  { key: "artifacts", label: "Files / hashes", render: (x) => <><code>{x.name}</code> <span className="text-[12px] text-muted">{x.type}</span> <code className="text-[11px] text-dim">{x.sha256}</code></>, to: (x) => `/analysis/${x.analysis_id}/static?artifact=${x.id}` },
  { key: "iocs", label: "IOCs (URL, domain, IP…)", render: (x) => <><Badge>{x.type}</Badge> <code className="break-any">{x.value}</code></>, to: (x) => `/analysis/${x.analysis_id}/iocs` },
  { key: "findings", label: "Findings", render: (x) => <><SeverityBadge severity={x.severity} /> <span className="font-mono text-dim">{x.id}</span> {x.title}</>, to: (x) => `/analysis/${x.analysis_id}/findings#${x.id}` },
  { key: "evidence", label: "Evidence (APIs, rules, observations)", render: (x) => <><SeverityBadge severity={x.severity} /> <span className="font-mono text-dim">{x.id}</span> {x.title} <code className="text-[11px] text-muted">{x.value}</code></>, to: (x) => `/analysis/${x.analysis_id}/evidence#${x.id}` },
  { key: "mitre", label: "MITRE techniques", render: (x) => <><Badge tone="accent">{x.technique_id}</Badge> {x.name}</>, to: (x) => `/analysis/${x.analysis_id}/mitre` },
  { key: "strings", label: "Strings", render: (x) => <><Badge>{x.classification}</Badge> <code className="break-any">{x.value}</code></>, to: (x) => `/analysis/${x.analysis_id}/static?artifact=${x.artifact_id}` },
];

export default function SearchPage() {
  const [params] = useSearchParams();
  const q = params.get("q") || "";
  const { data, loading, error } = useAsync(() => (q.length >= 2 ? api.search(q) : Promise.resolve(null)), [q]);
  const total = data ? Object.values(data).reduce((n, v) => n + v.length, 0) : 0;
  return (
    <div className="mx-auto max-w-6xl space-y-4 p-6">
      <h1 className="text-2xl font-bold">Search MALX <span className="font-mono text-base text-muted">“{q}”</span></h1>
      {error && <Empty>{error}</Empty>}
      {loading ? <Spinner /> : !data ? <Empty>Type at least two characters in the search bar.</Empty> : total === 0 ? <Empty>No results.</Empty> : (
        SECTIONS.filter((s) => data[s.key]?.length).map((s) => (
          <Card key={s.key} title={`${s.label} (${data[s.key].length})`} pad={false}>
            <ul className="divide-y divide-line/60">
              {data[s.key].map((x: any, i: number) => (
                <li key={i}><Link to={s.to(x)} className="flex flex-wrap items-center gap-2 px-4 py-2 text-[13px] hover:bg-panel2">{s.render(x)}</Link></li>
              ))}
            </ul>
          </Card>
        ))
      )}
    </div>
  );
}
