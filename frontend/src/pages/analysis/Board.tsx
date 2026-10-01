import {
  addEdge, Background, type Connection, Controls, type Edge, Handle, MarkerType, type Node, type NodeProps, Position, ReactFlow,
  ReactFlowProvider, useEdgesState, useNodesState, useReactFlow,
} from "@xyflow/react";
import { Lightbulb, Plus, Save, StickyNote, Target } from "lucide-react";
import { type DragEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../api/client";
import type { AnalystState, Evidence, Finding } from "../../api/types";
import { Badge, Button, Card, cx, Input, SeverityBadge, Spinner } from "../../components/ui";
import { SEV_COLOR } from "../../lib/format";
import { useAsync } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

const STATES: AnalystState[] = ["UNKNOWN", "INVESTIGATING", "SUPPORTED", "CONFIRMED", "DISMISSED"];
const STATE_COLOR: Record<AnalystState, string> = { UNKNOWN: "#56687c", INVESTIGATING: "#38bdf8", SUPPORTED: "#facc15", CONFIRMED: "#f43f5e", DISMISSED: "#2a3a4f" };

type BoardData = { kind: "evidence" | "finding" | "hypothesis" | "note"; ref?: string; label: string; severity?: string; state: AnalystState; text?: string; onChange?: (patch: any) => void };

function BoardNode({ id, data, selected }: NodeProps<Node<BoardData>>) {
  const color = STATE_COLOR[data.state];
  const Icon = data.kind === "hypothesis" ? Lightbulb : data.kind === "note" ? StickyNote : Target;
  return (
    <div className={cx("w-60 rounded-lg border bg-panel2 p-2 shadow-xl", selected && "ring-2 ring-accent/60", data.state === "DISMISSED" && "opacity-50")}
      style={{ borderColor: color, borderTop: `3px solid ${data.severity ? SEV_COLOR[data.severity as keyof typeof SEV_COLOR] : color}` }}>
      <Handle type="target" position={Position.Left} />
      <div className="mb-1 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-muted">
        <Icon className="h-3 w-3" /> {data.kind} {data.ref && <span className="font-mono text-dim">{data.ref}</span>}
      </div>
      {data.kind === "hypothesis" || data.kind === "note" ? (
        <textarea className="nodrag w-full resize-none rounded bg-panel3 p-1 text-[12px] text-text outline-none" rows={data.kind === "note" ? 3 : 2}
          value={data.text ?? data.label} onChange={(e) => data.onChange?.({ text: e.target.value, label: e.target.value.slice(0, 80) })} />
      ) : (
        <div className="text-[12px] leading-snug">{data.label}</div>
      )}
      <select className="nodrag mt-1.5 w-full rounded border border-line2 bg-panel px-1 py-0.5 text-[11px]" value={data.state}
        onChange={(e) => data.onChange?.({ state: e.target.value })} style={{ color }}>
        {STATES.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
      <Handle type="source" position={Position.Right} />
      <span className="hidden">{id}</span>
    </div>
  );
}
const nodeTypes = { board: BoardNode };

function Palette({ evidence, findings }: { evidence: Evidence[]; findings: Finding[] }) {
  const [q, setQ] = useState("");
  const start = (e: DragEvent, payload: object) => e.dataTransfer.setData("application/malx", JSON.stringify(payload));
  const ev = evidence.filter((e) => e.severity !== "info" && (!q || e.title.toLowerCase().includes(q.toLowerCase())));
  return (
    <Card title="Drag onto the board" pad={false} className="flex max-h-[76vh] flex-col">
      <div className="space-y-2 border-b border-line p-3">
        <div className="flex gap-2">
          <div draggable onDragStart={(e) => start(e, { kind: "hypothesis", label: "New hypothesis" })} className="flex-1 cursor-grab rounded-lg border border-dashed border-accent/60 p-2 text-center text-[12px] text-accent"><Lightbulb className="mx-auto h-4 w-4" /> Hypothesis</div>
          <div draggable onDragStart={(e) => start(e, { kind: "note", label: "Note" })} className="flex-1 cursor-grab rounded-lg border border-dashed border-line2 p-2 text-center text-[12px] text-muted"><StickyNote className="mx-auto h-4 w-4" /> Note</div>
        </div>
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter evidence" className="w-full" />
      </div>
      <div className="flex-1 space-y-1 overflow-auto p-2">
        <div className="px-1 text-[10px] font-bold uppercase tracking-wider text-muted">Findings</div>
        {findings.map((f) => (
          <div key={f.id} draggable onDragStart={(e) => start(e, { kind: "finding", ref: f.id, label: f.title, severity: f.severity })}
            className="cursor-grab rounded border border-line bg-panel2 px-2 py-1 text-[12px] hover:border-line2"><SeverityBadge severity={f.severity} /> <span className="font-mono text-dim">{f.id}</span> {f.title}</div>
        ))}
        <div className="px-1 pt-2 text-[10px] font-bold uppercase tracking-wider text-muted">Evidence</div>
        {ev.map((e) => (
          <div key={e.id} draggable onDragStart={(d) => start(d, { kind: "evidence", ref: e.id, label: e.title, severity: e.severity })}
            className="cursor-grab rounded border border-line bg-panel2 px-2 py-1 text-[12px] hover:border-line2"><SeverityBadge severity={e.severity} /> <span className="font-mono text-dim">{e.id}</span> {e.title}</div>
        ))}
      </div>
    </Card>
  );
}

function BoardInner({ evidence, findings, initial }: { evidence: Evidence[]; findings: Finding[]; initial: { nodes: any[]; edges: any[]; notes: string | null } }) {
  const { a } = useAnalysis();
  const rf = useReactFlow();
  const wrapper = useRef<HTMLDivElement>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<BoardData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(initial.edges || []);
  const [notes, setNotes] = useState(initial.notes || "");
  const [saved, setSaved] = useState<"saved" | "dirty" | "saving">("saved");
  const [msg, setMsg] = useState<string | null>(null);

  const patchNode = useCallback((id: string, patch: any) => {
    setNodes((ns) => ns.map((n) => (n.id === id ? { ...n, data: { ...n.data, ...patch } } : n)));
    setSaved("dirty");
  }, [setNodes]);
  const withHandlers = useCallback((ns: Node<BoardData>[]) => ns.map((n) => ({ ...n, type: "board", data: { ...n.data, onChange: (p: any) => patchNode(n.id, p) } })), [patchNode]);
  useEffect(() => setNodes(withHandlers(initial.nodes || [])), []); // eslint-disable-line react-hooks/exhaustive-deps

  const save = useCallback(async () => {
    setSaved("saving");
    const clean = nodes.map(({ id, position, data }) => ({ id, position, type: "board", data: { kind: data.kind, ref: data.ref, label: data.label, severity: data.severity, state: data.state, text: data.text } }));
    await api.saveBoard(a.id, { nodes: clean, edges: edges.map(({ id, source, target, label }) => ({ id, source, target, label })), notes });
    setSaved("saved");
  }, [nodes, edges, notes, a.id]);
  useEffect(() => {
    if (saved !== "dirty") return;
    const t = setTimeout(save, 1200);
    return () => clearTimeout(t);
  }, [saved, save]);

  const onConnect = useCallback((c: Connection) => {
    setEdges((es) => addEdge({ ...c, label: "relates", markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#38bdf8" } }, es));
    setSaved("dirty");
  }, [setEdges]);
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    const raw = e.dataTransfer.getData("application/malx");
    if (!raw) return;
    const p = JSON.parse(raw);
    const position = rf.screenToFlowPosition({ x: e.clientX, y: e.clientY });
    const id = `${p.kind}:${p.ref || crypto.randomUUID().slice(0, 8)}`;
    if (nodes.some((n) => n.id === id)) return;
    setNodes((ns) => [...ns, ...withHandlers([{ id, position, type: "board", data: { ...p, state: p.kind === "hypothesis" ? "INVESTIGATING" : "UNKNOWN", text: p.kind === "note" || p.kind === "hypothesis" ? p.label : undefined } }])]);
    setSaved("dirty");
  };
  const selectedEvidence = useMemo(() => nodes.filter((n) => n.selected && n.data.kind === "evidence").map((n) => n.data.ref!), [nodes]);
  const createFinding = async () => {
    const hyp = nodes.find((n) => n.selected && n.data.kind === "hypothesis");
    const title = hyp?.data.text || prompt("Finding title", "Analyst finding") || "";
    if (!title || title.length < 3) return;
    const res = await api.createFinding(a.id, { title: title.slice(0, 300), severity: "medium", what: title, why: "Created from the investigation board.", evidence: selectedEvidence, status: hyp?.data.state === "CONFIRMED" ? "CONFIRMED" : "SUPPORTED" });
    setMsg(`Created ${res.id} with ${selectedEvidence.length} evidence item(s).`);
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[300px_1fr]">
      <Palette evidence={evidence} findings={findings} />
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary" onClick={createFinding} disabled={!selectedEvidence.length}><Plus className="h-4 w-4" /> Create finding from selection ({selectedEvidence.length})</Button>
          <Button onClick={save}><Save className="h-4 w-4" /> Save</Button>
          <Badge tone={saved === "saved" ? "ok" : "default"}>{saved}</Badge>
          {msg && <span className="text-[12px] text-ok">{msg}</span>}
          <span className="ml-auto text-[11px] text-muted">Shift-click to multi-select · drag handles to connect · Delete to remove</span>
        </div>
        <div ref={wrapper} className="grid-bg h-[64vh] overflow-hidden rounded-xl border border-line bg-bg" onDragOver={(e) => e.preventDefault()} onDrop={onDrop}>
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={(c) => { onNodesChange(c); if (c.some((x) => x.type !== "select" && x.type !== "dimensions")) setSaved("dirty"); }}
            onEdgesChange={(c) => { onEdgesChange(c); setSaved("dirty"); }} onConnect={onConnect} fitView={(initial.nodes || []).length > 0}
            fitViewOptions={{ maxZoom: 1 }} defaultViewport={{ x: 0, y: 0, zoom: 0.9 }} maxZoom={1.5} proOptions={{ hideAttribution: true }} deleteKeyCode={["Delete", "Backspace"]}>
            <Background color="#1d2a3a" gap={24} />
            <Controls />
          </ReactFlow>
        </div>
        <textarea value={notes} onChange={(e) => { setNotes(e.target.value); setSaved("dirty"); }} rows={3} placeholder="Case notes…"
          className="w-full rounded-lg border border-line2 bg-panel2 px-3 py-2 text-[13px] outline-none focus:border-accent/60" />
        <div className="flex flex-wrap gap-2 text-[11px]">{STATES.map((s) => <span key={s} className="flex items-center gap-1 text-muted"><i className="inline-block h-2 w-2 rounded-full" style={{ background: STATE_COLOR[s] }} />{s}</span>)}</div>
      </div>
    </div>
  );
}

export default function BoardPage() {
  const { a, completed } = useAnalysis();
  const ev = useAsync(() => (completed ? api.evidence(a.id) : Promise.resolve([])), [a.id, completed]);
  const fs = useAsync(() => (completed ? api.findings(a.id) : Promise.resolve([])), [a.id, completed]);
  const board = useAsync(() => (completed ? api.board(a.id) : Promise.resolve(null)), [a.id, completed]);
  if (!completed) return <NotReady />;
  if (!ev.data || !fs.data || !board.data) return <Spinner />;
  return <ReactFlowProvider><BoardInner evidence={ev.data} findings={fs.data} initial={board.data} /></ReactFlowProvider>;
}

