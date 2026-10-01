import { ChevronLeft, ChevronRight } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api/client";
import { Button, Input } from "./ui";

const PAGE = 512;

/** Read-only hex view. The backend returns hex text; the sample is never downloaded. */
export default function HexView({ analysisId, artifactId, initialOffset = 0 }: { analysisId: string; artifactId: string; initialOffset?: number }) {
  const [offset, setOffset] = useState(initialOffset);
  const [data, setData] = useState<{ hex: string; size: number } | null>(null);
  const [goto, setGoto] = useState("");
  useEffect(() => {
    api.hex(analysisId, artifactId, offset, PAGE).then(setData).catch(() => setData(null));
  }, [analysisId, artifactId, offset]);
  useEffect(() => setOffset(initialOffset), [initialOffset]);
  const bytes = data ? data.hex.match(/../g) || [] : [];
  const rows = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const ascii = chunk.map((b) => {
      const c = parseInt(b, 16);
      return c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
    }).join("");
    rows.push({ off: offset + i, chunk, ascii });
  }
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Button variant="ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}><ChevronLeft className="h-4 w-4" /></Button>
        <span className="font-mono text-[12px] text-muted">0x{offset.toString(16)} – 0x{(offset + bytes.length).toString(16)} of 0x{(data?.size || 0).toString(16)}</span>
        <Button variant="ghost" disabled={!data || offset + PAGE >= data.size} onClick={() => setOffset(offset + PAGE)}><ChevronRight className="h-4 w-4" /></Button>
        <form className="ml-auto flex gap-2" onSubmit={(e) => {
          e.preventDefault();
          const v = goto.trim().toLowerCase();
          const n = v.startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10);
          if (!isNaN(n) && n >= 0) setOffset(n - (n % 16));
        }}>
          <Input value={goto} onChange={(e) => setGoto(e.target.value)} placeholder="offset (0x…)" className="w-32 font-mono" />
          <Button type="submit">Go</Button>
        </form>
      </div>
      <div className="overflow-x-auto rounded-lg border border-line bg-bg p-3 font-mono text-[12px] leading-5">
        {rows.map((r) => (
          <div key={r.off} className="flex gap-4 whitespace-pre">
            <span className="text-dim">{r.off.toString(16).padStart(8, "0")}</span>
            <span className="text-text/90">{r.chunk.map((b, i) => (i === 8 ? " " : "") + b).join(" ").padEnd(49, " ")}</span>
            <span className="text-accent/80">{r.ascii}</span>
          </div>
        ))}
        {!rows.length && <span className="text-muted">No data.</span>}
      </div>
    </div>
  );
}
