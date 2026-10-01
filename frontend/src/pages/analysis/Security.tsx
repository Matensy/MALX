import { Background, Controls, type Edge, MarkerType, type Node, Position, ReactFlow } from "@xyflow/react";
import { FileCode2, KeyRound, Package, Route } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { Badge, Card, cx, Empty, Input, KV, SeverityBadge, Spinner, Table, Tabs } from "../../components/ui";
import { layoutDagre } from "../../lib/graph";
import { useAsync } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

function Surface({ surface }: { surface: any }) {
  const [sel, setSel] = useState<any>(null);
  const { nodes, edges } = useMemo(() => {
    const ns: Node[] = surface.nodes.map((n: any) => {
      const risky = (n.risk || []).length > 0 || (n.unauthenticated || []).length > 0;
      return {
        id: n.id, position: { x: 0, y: 0 }, sourcePosition: Position.Right, targetPosition: Position.Left, data: { label: `${n.label}${n.risk?.length ? ` · ${n.risk.length} risk` : ""}` },
        style: { background: n.type === "root" ? "#38bdf822" : risky ? "#f43f5e18" : "#111a25", border: `1px solid ${n.type === "root" ? "#38bdf8" : risky ? "#f43f5e88" : "#2a3a4f"}`,
          color: "#d8e3ee", borderRadius: 10, fontSize: 12, width: 200, padding: 8 },
      };
    });
    const es: Edge[] = surface.edges.map((e: any, i: number) => ({ id: `s${i}`, source: e.source, target: e.target, markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#56687c" } }));
    return { nodes: layoutDagre(ns, es, "LR", () => ({ w: 200, h: 44 }), { ranksep: 120, nodesep: 20 }), edges: es };
  }, [surface]);
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_380px]">
      <div className="h-[420px] rounded-xl border border-line bg-bg">
        <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }} nodesDraggable={false}
          onNodeClick={(_, n) => setSel(surface.nodes.find((x: any) => x.id === n.id))}>
          <Background color="#1d2a3a" gap={22} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <Card title={sel ? sel.label : "Attack surface element"}>
        {!sel || sel.type === "root" ? <div className="text-[13px] text-muted">Select an element to see its risk indicators, evidence, dependencies and potential attack paths.</div> : (
          <KV rows={[
            ["Risk indicators", sel.risk?.length ? <ul className="space-y-0.5">{sel.risk.map((r: string) => <li key={r}>• {r}</li>)}</ul> : "none"],
            ["Evidence", <div className="flex flex-wrap gap-1">{(sel.evidence || []).map((e: string) => <Link key={e} to={`../evidence#${e}`} className="font-mono text-[12px] text-accent">{e}</Link>)}</div>],
            ["Dependencies", sel.dependencies?.join(", ") || "—"],
            ["Endpoints", sel.endpoints?.length ? <div className="font-mono text-[11.5px]">{sel.endpoints.join(" · ")}</div> : "—"],
            ["No auth hint", sel.unauthenticated?.length ? <div className="font-mono text-[11.5px] text-sev-high">{sel.unauthenticated.join(" · ")}</div> : "—"],
            ["Attack paths", <ul className="space-y-0.5">{(sel.paths || []).map((p: string) => <li key={p} className="text-sev-high">{p}</li>)}</ul>],
          ]} />
        )}
      </Card>
    </div>
  );
}

export default function SecurityPage() {
  const { a, completed } = useAnalysis();
  const { data, loading } = useAsync(() => (completed ? api.appsec(a.id) : Promise.resolve(null)), [a.id, completed]);
  const [tab, setTab] = useState<"code" | "secrets" | "deps" | "endpoints" | "surface">("surface");
  const [q, setQ] = useState("");
  if (!completed) return <NotReady />;
  if (loading && !data) return <Spinner />;
  if (!data?.enabled) {
    return <Empty icon={<FileCode2 className="h-6 w-6" />}>Application security mode did not run: no project/source tree was detected. Re-submit with the <b>Application security</b> mode to force it. Secret detection in binaries still appears under Evidence.</Empty>;
  }
  const vulnByDep = new Map<string, any[]>();
  for (const v of data.vulnerabilities) vulnByDep.set(v.dependency_id, [...(vulnByDep.get(v.dependency_id) || []), v]);
  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-4">
        <Card title="Languages"><div className="flex flex-wrap gap-1">{data.languages.map((l: any) => <Badge key={l.language}>{l.language} · {l.files} files · {l.lines} LOC</Badge>)}</div></Card>
        <Card title="Frameworks"><div className="flex flex-wrap gap-1">{data.frameworks.length ? data.frameworks.map((f: string) => <Badge key={f} tone="accent">{f}</Badge>) : <span className="text-muted">—</span>}</div></Card>
        <Card title="Dependencies"><div className="text-2xl font-bold">{data.dependencies.length}</div><div className="text-[12px] text-muted">{data.vulnerabilities.length} with advisories · DB: {data.advisory_database?.advisories ?? 0} advisories</div></Card>
        <Card title="Exposure"><div className="text-2xl font-bold">{data.code_findings.length}</div><div className="text-[12px] text-muted">weakness groups · {data.secrets.length} secrets · {data.endpoints.length} endpoints</div></Card>
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "surface", label: <span className="flex items-center gap-1"><Route className="h-3.5 w-3.5" /> Attack surface</span> },
        { id: "code", label: "Code weaknesses", count: data.code_findings.length },
        { id: "secrets", label: <span className="flex items-center gap-1"><KeyRound className="h-3.5 w-3.5" /> Secrets</span>, count: data.secrets.length },
        { id: "deps", label: <span className="flex items-center gap-1"><Package className="h-3.5 w-3.5" /> Dependencies</span>, count: data.dependencies.length },
        { id: "endpoints", label: "Endpoints", count: data.endpoints.length },
      ]} />
      {tab === "surface" && <Surface surface={data.attack_surface} />}
      {tab === "code" && (
        <div className="space-y-2">
          {data.code_findings.length === 0 && <Empty>No code weakness patterns matched.</Empty>}
          {data.code_findings.map((f: any) => (
            <Card key={f.id} title={<span className="flex items-center gap-2 normal-case tracking-normal text-text"><SeverityBadge severity={f.severity} /> {f.title} {f.cwe && <Badge>{f.cwe}</Badge>}</span>}
              actions={<Link to={`../findings#${f.id}`} className="font-mono text-[12px] text-accent">{f.id}</Link>}>
              <p className="text-[13px] text-muted">{f.why}</p>
              <ul className="mt-2 space-y-0.5 font-mono text-[12px]">{f.where.map((w: string) => <li key={w}>{w}</li>)}</ul>
              {f.recommendation && <p className="mt-2 text-[12px] text-ok">→ {f.recommendation}</p>}
            </Card>
          ))}
        </div>
      )}
      {tab === "secrets" && (
        <Card pad={false}>
          <Table head={["Severity", "Type", "Location", "Masked value", "Evidence"]} empty="No secrets detected."
            rows={data.secrets.map((s: any) => [<SeverityBadge severity={s.severity} />, s.title, <code className="text-[12px]">{s.location}</code>, <code className="text-[12px]">{s.masked}</code>,
              <Link to={`../evidence#${s.evidence_ref}`} className="font-mono text-[12px] text-accent">{s.evidence_ref}</Link>])} />
          <p className="p-3 text-[12px] text-dim">Secrets are masked before storage; MALX never keeps or displays the full value.</p>
        </Card>
      )}
      {tab === "deps" && (
        <Card pad={false} actions={<Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter" />} title="Dependency graph (application → manifest → package)">
          <Table head={["Package", "Ecosystem", "Version", "Manifest", "Scope", "Advisories"]}
            rows={data.dependencies.filter((d: any) => !q || d.name.toLowerCase().includes(q.toLowerCase())).map((d: any) => {
              const v = vulnByDep.get(d.id) || [];
              return [<span className={cx("font-mono", v.length > 0 && "text-sev-high")}>{d.name}</span>, d.ecosystem, <code>{d.version || d.version_spec || "—"}</code>,
                <code className="text-[11.5px] text-muted">{d.manifest}</code>, `${d.direct ? "direct" : "transitive"}${d.dev ? " · dev" : ""}`,
                v.length ? v.map((x) => <div key={x.advisory_id}><SeverityBadge severity={x.severity} /> <span className="font-mono text-[12px]">{x.advisory_id}</span> <span className="text-[11px] text-muted">fixed {x.fixed_version || "?"}</span></div>) : <span className="text-dim">—</span>];
            })} />
          {!data.advisory_database?.advisories && <p className="p-3 text-[12px] text-sev-medium">No local advisory database imported — vulnerability matching is disabled. Import OSV data offline with <code>python scripts/import_osv.py</code>. MALX never invents CVEs.</p>}
        </Card>
      )}
      {tab === "endpoints" && (
        <Card pad={false}>
          <Table head={["Method", "Path", "Framework", "Kinds", "Auth hint", "Location"]}
            rows={data.endpoints.map((e: any) => [<Badge>{e.method}</Badge>, <code>{e.path}</code>, e.framework, e.kinds.join(", "),
              e.auth_hint ? <Badge tone="ok">yes</Badge> : <Badge tone="warn">none found</Badge>, <code className="text-[11.5px] text-muted">{e.file}:{e.line}</code>])} />
        </Card>
      )}
    </div>
  );
}
