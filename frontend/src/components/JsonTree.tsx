import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

/** Generic collapsible viewer for structured metadata. Values are rendered as text only. */
export default function JsonTree({ value, name, depth = 0 }: { value: any; name?: string; depth?: number }) {
  const [open, setOpen] = useState(depth < 1);
  const isObj = value && typeof value === "object";
  if (!isObj) {
    return (
      <div className="flex gap-2 py-0.5 font-mono text-[12px]">
        {name !== undefined && <span className="text-muted">{name}:</span>}
        <span className="break-any text-text/90">{value === null ? "null" : typeof value === "string" ? value : String(value)}</span>
      </div>
    );
  }
  const entries = Array.isArray(value) ? value.map((v, i) => [String(i), v] as [string, any]) : Object.entries(value);
  return (
    <div className="font-mono text-[12px]">
      <button type="button" className="flex items-center gap-1 py-0.5 text-muted hover:text-text" onClick={() => setOpen(!open)}>
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {name !== undefined && <span>{name}</span>}
        <span className="text-dim">{Array.isArray(value) ? `[${value.length}]` : `{${entries.length}}`}</span>
      </button>
      {open && (
        <div className="ml-3 border-l border-line pl-3">
          {entries.slice(0, 500).map(([k, v]) => <JsonTree key={k} name={k} value={v} depth={depth + 1} />)}
          {entries.length > 500 && <div className="text-dim">… {entries.length - 500} more</div>}
        </div>
      )}
    </div>
  );
}
