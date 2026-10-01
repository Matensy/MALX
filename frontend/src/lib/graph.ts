import dagre from "@dagrejs/dagre";
import type { Edge, Node } from "@xyflow/react";

export function layoutDagre<N extends Node, E extends Edge>(nodes: N[], edges: E[], dir: "LR" | "TB" = "LR",
  size: (n: N) => { w: number; h: number } = () => ({ w: 220, h: 64 }), opts: { ranksep?: number; nodesep?: number } = {}) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: dir, ranksep: opts.ranksep ?? 90, nodesep: opts.nodesep ?? 18, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of nodes) {
    const { w, h } = size(n);
    g.setNode(n.id, { width: w, height: h });
  }
  for (const e of edges) if (g.hasNode(e.source) && g.hasNode(e.target)) g.setEdge(e.source, e.target);
  dagre.layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id);
    const { w, h } = size(n);
    return { ...n, position: { x: (p?.x ?? 0) - w / 2, y: (p?.y ?? 0) - h / 2 } };
  });
}
