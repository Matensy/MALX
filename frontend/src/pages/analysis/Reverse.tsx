import { Background, Controls, type Edge, MarkerType, type Node, Position, ReactFlow } from "@xyflow/react";
import { Cpu, FunctionSquare } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import type { ReverseFunction } from "../../api/types";
import HexView from "../../components/HexView";
import { Badge, Card, cx, Empty, Input, KV, Mono, SeverityBadge, Spinner, Tabs } from "../../components/ui";
import { bytes } from "../../lib/format";
import { layoutDagre } from "../../lib/graph";
import { useAsync } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

const MNEM_COLOR: Record<string, string> = { call: "#38bdf8", jmp: "#c084fc", ret: "#f43f5e", push: "#94a3b8", pop: "#94a3b8", lea: "#34d399", mov: "#d8e3ee" };

function Assembly({ fn, onCall }: { fn: ReverseFunction; onCall: (name: string) => void }) {
  return (
    <div className="max-h-[560px] overflow-auto rounded-lg border border-line bg-bg p-3 font-mono text-[12px] leading-[1.55]">
      {fn.assembly?.map((i) => {
        const base = i.mnemonic.split(" ")[0];
        const color = MNEM_COLOR[base] || (base.startsWith("j") ? "#c084fc" : "#d8e3ee");
        return (
          <div key={i.address} className="flex gap-3 whitespace-pre hover:bg-panel2">
            <span className="w-28 shrink-0 text-dim">{i.address}</span>
            <span className="w-32 shrink-0 truncate text-dim/70">{i.bytes}</span>
            <span className="w-16 shrink-0 font-semibold" style={{ color }}>{i.mnemonic}</span>
            <span className="text-text/85">{i.operands}</span>
            {i.import && <span className="text-sev-high">; {i.import}</span>}
            {i.call && <button className="text-accent hover:underline" onClick={() => onCall(i.call!)}>; → {i.call}</button>}
            {i.string && <span className="text-ok">; "{i.string}"</span>}
          </div>
        );
      })}
      {fn.truncated && <div className="mt-2 text-sev-medium">… function truncated (instruction limit)</div>}
    </div>
  );
}

function CallGraph({ fn, onSelect }: { fn: ReverseFunction; onSelect: (name: string) => void }) {
  const { nodes, edges } = useMemo(() => {
    const ns: Node[] = [{ id: fn.name, data: { label: fn.name }, position: { x: 0, y: 0 }, style: { background: "#38bdf822", border: "1px solid #38bdf8", color: "#d8e3ee", borderRadius: 8, fontSize: 11, width: 180 } }];
    const es: Edge[] = [];
    fn.callers.slice(0, 12).forEach((c) => {
      ns.push({ id: `c:${c}`, data: { label: c }, position: { x: 0, y: 0 }, style: { background: "#111a25", border: "1px solid #2a3a4f", color: "#d8e3ee", borderRadius: 8, fontSize: 11, width: 180 } });
      es.push({ id: `e:${c}`, source: `c:${c}`, target: fn.name, markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#56687c" } });
    });
    fn.callees.slice(0, 16).forEach((c) => {
      ns.push({ id: `d:${c}`, data: { label: c }, position: { x: 0, y: 0 }, style: { background: "#111a25", border: "1px solid #2a3a4f", color: "#d8e3ee", borderRadius: 8, fontSize: 11, width: 180 } });
      es.push({ id: `f:${c}`, source: fn.name, target: `d:${c}`, markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#38bdf8" } });
    });
    fn.imports.slice(0, 12).forEach((imp) => {
      ns.push({ id: `i:${imp}`, data: { label: imp.split("!").pop() }, position: { x: 0, y: 0 }, style: { background: "#fb923c18", border: "1px solid #fb923c66", color: "#fb923c", borderRadius: 8, fontSize: 11, width: 180 } });
      es.push({ id: `g:${imp}`, source: fn.name, target: `i:${imp}`, markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#fb923c88", strokeDasharray: "4 3" } });
    });
    const lr = ns.map((n) => ({ ...n, sourcePosition: Position.Right, targetPosition: Position.Left }));
    return { nodes: layoutDagre(lr, es, "LR", () => ({ w: 180, h: 36 }), { ranksep: 70, nodesep: 10 }), edges: es };
  }, [fn]);
  return (
    <div className="h-80 rounded-lg border border-line bg-bg">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }} nodesDraggable={false}
        onNodeClick={(_, n) => { const name = n.id.replace(/^[cd]:/, ""); if (!n.id.startsWith("i:") && name !== fn.name) onSelect(name); }}>
        <Background color="#1d2a3a" gap={20} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function FunctionDetail({ aid, artifactId, fname, onSelect }: { aid: string; artifactId: string; fname: string; onSelect: (n: string) => void }) {
  const { data: fn, loading, error } = useAsync(() => api.fn(aid, artifactId, fname), [aid, artifactId, fname]);
  const [tab, setTab] = useState<"asm" | "pseudo" | "graph">("asm");
  if (loading && !fn) return <Spinner />;
  if (error || !fn) return <Empty>{error || "Function not found"}</Empty>;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <FunctionSquare className="h-5 w-5 text-accent" />
        <h2 className="font-mono text-lg font-bold">{fn.name}</h2>
        <Mono copy>{fn.address}</Mono>
        <Badge>{fn.source}</Badge>
        <span className="text-[12px] text-muted">{fn.instructions} instructions · {bytes(fn.size)} · segment {fn.segment}</span>
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "asm", label: "Assembly" }, { id: "pseudo", label: "Pseudo-code" }, { id: "graph", label: "Call graph" }]} />
      {tab === "asm" && <Assembly fn={fn} onCall={onSelect} />}
      {tab === "pseudo" && (fn.pseudocode ? <pre className="max-h-[560px] overflow-auto rounded-lg border border-line bg-bg p-3 font-mono text-[12px]">{fn.pseudocode}</pre>
        : <Empty>{fn.pseudocode_note}</Empty>)}
      {tab === "graph" && <CallGraph fn={fn} onSelect={onSelect} />}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={`Imports referenced (${fn.imports.length})`}>
          <div className="flex flex-wrap gap-1">{fn.imports.map((i) => <span key={i} className="rounded border border-sev-high/40 bg-sev-high/10 px-1.5 py-0.5 font-mono text-[11.5px] text-sev-high">{i}</span>)}</div>
          {!fn.imports.length && <span className="text-[13px] text-muted">None.</span>}
        </Card>
        <Card title={`Strings referenced (${fn.strings.length})`}>
          <ul className="space-y-1">{fn.strings.map((s) => <li key={s.address} className="font-mono text-[12px]"><span className="text-dim">{s.address}</span> <span className="text-ok">"{s.value}"</span></li>)}</ul>
          {!fn.strings.length && <span className="text-[13px] text-muted">None.</span>}
        </Card>
        <Card title="Callers / callees / cross references">
          <KV rows={[
            ["Callers", fn.callers.length ? fn.callers.map((c) => <button key={c} className="mr-2 font-mono text-[12px] text-accent hover:underline" onClick={() => onSelect(c)}>{c}</button>) : "—"],
            ["Callees", fn.callees.length ? fn.callees.map((c) => <button key={c} className="mr-2 font-mono text-[12px] text-accent hover:underline" onClick={() => onSelect(c)}>{c}</button>) : "—"],
            ["Call sites", fn.xrefs.length ? <span className="font-mono text-[12px]">{fn.xrefs.slice(0, 30).join(", ")}</span> : "—"],
          ]} />
        </Card>
        <Card title="Entropy / context & related findings">
          <KV rows={[["Segment", fn.segment_info ? `${fn.segment_info.name} @ ${fn.segment_info.start}` : "—"],
            ["Segment entropy", fn.segment_info ? `${fn.segment_info.entropy} bits/byte` : "—"]]} />
          <ul className="mt-3 space-y-1.5">
            {fn.related?.map((r) => (
              <li key={r.evidence} className="flex items-center gap-2 text-[12px]">
                <SeverityBadge severity={r.severity} />
                <Link to={`../evidence#${r.evidence}`} className="font-mono text-dim hover:text-accent">{r.evidence}</Link>
                <span className="truncate">{r.title}</span>
                {r.findings.map((f) => <Link key={f} to={`../findings#${f}`} className="font-mono text-accent">{f}</Link>)}
              </li>
            ))}
            {!fn.related?.length && <li className="text-[12px] text-muted">No evidence linked to this function's imports/strings.</li>}
          </ul>
        </Card>
      </div>
    </div>
  );
}

export default function ReversePage() {
  const { a, completed } = useAnalysis();
  const [params, setParams] = useSearchParams();
  const candidates = a.artifacts.filter((x) => x.has_reverse);
  const artifactId = params.get("artifact") || candidates[0]?.id;
  const funcs = useAsync(() => (artifactId && completed ? api.functions(a.id, artifactId) : Promise.resolve(null)), [a.id, artifactId, completed]);
  const [filter, setFilter] = useState("");
  const [onlyApi, setOnlyApi] = useState(false);
  const fname = params.get("fn") || funcs.data?.functions?.[0]?.name;
  if (!completed) return <NotReady />;
  if (!candidates.length) {
    return <Empty icon={<Cpu className="h-6 w-6" />}>No native PE/ELF code was disassembled in this analysis. The built-in engine (Capstone) handles x86/x64/ARM; Ghidra or radare2 add pseudo-code when installed.</Empty>;
  }
  const list = (funcs.data?.functions || []).filter((f: ReverseFunction) =>
    (!filter || f.name.toLowerCase().includes(filter.toLowerCase()) || f.imports.some((i) => i.toLowerCase().includes(filter.toLowerCase()))) && (!onlyApi || f.imports.length));
  const select = (name: string) => setParams({ artifact: artifactId!, fn: name });
  return (
    <div className="grid gap-4 xl:grid-cols-[320px_1fr]">
      <div className="space-y-3">
        {candidates.length > 1 && (
          <select className="w-full rounded-lg border border-line2 bg-panel2 px-2 py-1.5 text-[13px]" value={artifactId} onChange={(e) => setParams({ artifact: e.target.value })}>
            {candidates.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        )}
        <Card title={`Functions (${funcs.data?.function_count ?? 0})`} pad={false}>
          <div className="space-y-2 border-b border-line p-3">
            <div className="text-[11px] text-muted">{funcs.data?.engine} · {funcs.data?.arch} · {funcs.data?.instruction_count} instructions{funcs.data?.truncated ? " (truncated)" : ""}</div>
            <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by name or API" className="w-full" />
            <label className="flex items-center gap-2 text-[12px] text-muted"><input type="checkbox" checked={onlyApi} onChange={(e) => setOnlyApi(e.target.checked)} /> only functions referencing imports</label>
          </div>
          <ul className="max-h-[65vh] overflow-auto">
            {list.map((f: ReverseFunction) => (
              <li key={f.address}>
                <button onClick={() => select(f.name)} className={cx("flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-panel2", fname === f.name && "bg-accent/10")}>
                  <span className="truncate font-mono text-[12px]">{f.name}</span>
                  {f.imports.length > 0 && <Badge tone="warn" className="ml-auto">{f.imports.length} API</Badge>}
                </button>
              </li>
            ))}
          </ul>
        </Card>
      </div>
      <div className="min-w-0 space-y-4">
        {fname && artifactId ? <FunctionDetail aid={a.id} artifactId={artifactId} fname={fname} onSelect={select} /> : <Spinner />}
        {artifactId && <Card title="Hex (entry region)"><HexView analysisId={a.id} artifactId={artifactId} /></Card>}
      </div>
    </div>
  );
}
