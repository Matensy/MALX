import { Background, Controls, type Edge, Handle, MarkerType, MiniMap, type Node, type NodeProps, Position, ReactFlow } from "@xyflow/react";
import { Box, Cog, FileSearch, Gavel, Network, Shield, Target } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import type { GraphData, GraphNode } from "../../api/types";
import { Badge, Button, Card, cx, Empty, KV, SeverityBadge, Spinner } from "../../components/ui";
import { SEV_COLOR } from "../../lib/format";
import { layoutDagre } from "../../lib/graph";
import { useAsync } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

const TYPE_META: Record<string, { icon: any; color: string; label: string }> = {
  sample: { icon: Box, color: "#38bdf8", label: "Sample" },
  artifact: { icon: Box, color: "#818cf8", label: "Artifact" },
  engine: { icon: Cog, color: "#94a3b8", label: "Engine" },
  evidence: { icon: FileSearch, color: "#facc15", label: "Evidence" },
  finding: { icon: Target, color: "#f43f5e", label: "Finding" },
  mitre: { icon: Shield, color: "#c084fc", label: "MITRE" },
  classification: { icon: Gavel, color: "#f43f5e", label: "Classification" },
};

type GNode = Node<{ g: GraphNode; dim: boolean }>;

function MalxNode({ data }: NodeProps<GNode>) {
  const g = data.g;
  const meta = TYPE_META[g.type];
  const Icon = meta.icon;
  const color = g.severity ? SEV_COLOR[g.severity] : meta.color;
  return (
    <div className={cx("w-[230px] rounded-lg border bg-panel2 px-2.5 py-1.5 shadow-lg transition", data.dim && "opacity-25")}
      style={{ borderColor: `${color}88`, borderLeft: `3px solid ${color}` }}>
      <Handle type="target" position={Position.Left} />
      <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider" style={{ color: meta.color }}>
        <Icon className="h-3 w-3" /> {meta.label} {g.type === "evidence" || g.type === "finding" ? <span className="font-mono text-dim">{g.ref}</span> : null}
      </div>
      <div className="truncate text-[12px] font-medium text-text" title={g.label}>{g.label}</div>
      {g.sublabel && <div className="truncate font-mono text-[10.5px] text-muted" title={g.sublabel}>{g.sublabel}</div>}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const nodeTypes = { malx: MalxNode };

function connected(data: GraphData, start: string): Set<string> {
  const keep = new Set([start]);
  const up = new Map<string, string[]>();
  const down = new Map<string, string[]>();
  for (const e of data.edges) {
    (up.get(e.target) || up.set(e.target, []).get(e.target)!).push(e.source);
    (down.get(e.source) || down.set(e.source, []).get(e.source)!).push(e.target);
  }
  const walk = (m: Map<string, string[]>, id: string) => {
    for (const n of m.get(id) || []) if (!keep.has(n)) { keep.add(n); walk(m, n); }
  };
  walk(up, start);
  walk(down, start);
  return keep;
}

export default function GraphPage() {
  const { a, completed } = useAnalysis();
  const [params, setParams] = useSearchParams();
  const [weak, setWeak] = useState(false);
  const { data, loading } = useAsync(() => (completed ? api.graph(a.id, weak) : Promise.resolve(null)), [a.id, completed, weak]);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const focus = params.get("focus");
  const focusId = focus ? (focus.startsWith("F-") ? `f:${focus}` : focus.startsWith("EV-") ? `ev:${focus}` : focus) : null;

  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [] as GNode[], edges: [] as Edge[] };
    const keep = focusId ? connected(data, focusId) : null;
    const ns: GNode[] = data.nodes.map((g) => ({ id: g.id, type: "malx", position: { x: 0, y: 0 }, data: { g, dim: !!keep && !keep.has(g.id) } }));
    const es: Edge[] = data.edges.map((e, i) => {
      const dim = !!keep && !(keep.has(e.source) && keep.has(e.target));
      return {
        id: `e${i}`, source: e.source, target: e.target, label: ["analyzed_by", "contains"].includes(e.relationship) ? undefined : e.relationship,
        markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
        style: { stroke: e.relationship === "supports" ? "#f43f5e99" : e.relationship === "maps_to" ? "#c084fc99" : "#2a3a4f", opacity: dim ? 0.12 : 1, strokeWidth: e.relationship === "supports" ? 1.6 : 1 },
        animated: !!focusId && !dim && e.relationship === "supports",
      };
    });
    return { nodes: layoutDagre(ns, es, "LR", () => ({ w: 230, h: 56 }), { ranksep: 110, nodesep: 12 }), edges: es };
  }, [data, focusId]);

  if (!completed) return <NotReady />;
  if (loading && !data) return <Spinner />;
  if (!data || data.nodes.length <= 1) return <Empty icon={<Network className="h-6 w-6" />}>Nothing to graph yet.</Empty>;
  const findings = data.nodes.filter((n) => n.type === "finding");
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
      <div className="h-[72vh] overflow-hidden rounded-xl border border-line bg-bg">
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView minZoom={0.1} proOptions={{ hideAttribution: true }}
          onNodeClick={(_, n) => setSelected((n.data as any).g)} nodesConnectable={false}>
          <Background color="#1d2a3a" gap={24} />
          <MiniMap pannable zoomable nodeColor={(n) => { const g = (n.data as any).g as GraphNode; return g.severity ? SEV_COLOR[g.severity] : TYPE_META[g.type].color; }} maskColor="#070b11cc" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <div className="space-y-3">
        <Card title="Graph">
          <p className="text-[12px] text-muted">Sample → engines → evidence → findings → MITRE → classification. Every edge carries source, target, relationship, evidence id and confidence.</p>
          <label className="mt-2 flex items-center gap-2 text-[12px]"><input type="checkbox" checked={weak} onChange={(e) => setWeak(e.target.checked)} /> include weak / unlinked observations</label>
          <div className="mt-3 flex flex-wrap gap-1.5">{Object.entries(TYPE_META).map(([k, m]) => <Badge key={k}><i className="inline-block h-2 w-2 rounded-full" style={{ background: m.color }} />{m.label}</Badge>)}</div>
        </Card>
        <Card title="Focus a finding">
          <div className="flex flex-wrap gap-1.5">
            {findings.map((f) => (
              <button key={f.id} onClick={() => setParams(focus === f.ref ? {} : { focus: f.ref })}
                className={cx("rounded-md border px-2 py-0.5 font-mono text-[11px]", focus === f.ref ? "border-accent bg-accent/10 text-accent" : "border-line2 text-muted hover:text-text")}>{f.ref}</button>
            ))}
          </div>
          {focus && <Button variant="ghost" className="mt-2" onClick={() => setParams({})}>Clear focus</Button>}
        </Card>
        {selected && (
          <Card title={TYPE_META[selected.type].label}>
            <div className="mb-2 font-medium">{selected.label}</div>
            <KV rows={[["Ref", <code>{selected.ref}</code>], ["Detail", selected.sublabel || "—"], ["Severity", selected.severity ? <SeverityBadge severity={selected.severity} /> : "—"]]} />
            <div className="mt-3 flex gap-2">
              {selected.type === "evidence" && <Link to={`../evidence#${selected.ref}`}><Button>Open evidence</Button></Link>}
              {selected.type === "finding" && <><Link to={`../findings#${selected.ref}`}><Button>Open finding</Button></Link><Button onClick={() => setParams({ focus: selected.ref })}>Focus</Button></>}
              {(selected.type === "sample" || selected.type === "artifact") && <Link to={`../static?artifact=${selected.ref}`}><Button>Open artifact</Button></Link>}
              {selected.type === "mitre" && <a href={`https://attack.mitre.org/techniques/${selected.ref.replace(".", "/")}/`} target="_blank" rel="noreferrer noopener"><Button>ATT&CK page</Button></a>}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
