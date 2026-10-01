import { Download } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, urls } from "../../api/client";
import type { IOC } from "../../api/types";
import { Badge, Button, Card, CopyButton, Empty, Input, Spinner, Tabs } from "../../components/ui";
import { download } from "../../lib/format";
import { useAsync } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

export const IOC_TABS: { id: string; label: string; types: string[] }[] = [
  { id: "hashes", label: "Hashes", types: ["hash"] },
  { id: "domains", label: "Domains", types: ["domain", "onion"] },
  { id: "ips", label: "IPs", types: ["ipv4", "ipv6"] },
  { id: "urls", label: "URLs", types: ["url"] },
  { id: "files", label: "Files", types: ["file_path"] },
  { id: "registry", label: "Registry", types: ["registry"] },
  { id: "mutex", label: "Mutex", types: ["mutex"] },
  { id: "emails", label: "Emails", types: ["email"] },
  { id: "other", label: "Other", types: ["user_agent", "crypto_wallet"] },
];

export function IocTable({ items, showAnalysis }: { items: IOC[]; showAnalysis?: boolean }) {
  if (!items.length) return <Empty>No indicators of this type.</Empty>;
  return (
    <div className="max-h-[62vh] overflow-auto">
      <table className="w-full text-[13px]">
        <thead className="sticky top-0 bg-panel"><tr className="text-left text-[11px] uppercase tracking-wider text-muted">
          <th className="px-3 py-2">Value</th><th className="px-3 py-2">Type</th><th className="px-3 py-2">Context</th><th className="px-3 py-2">Evidence</th>
          {showAnalysis && <th className="px-3 py-2">Analysis</th>}</tr></thead>
        <tbody>
          {items.map((i, k) => (
            <tr key={k} className="border-t border-line/60 align-top">
              <td className="px-3 py-1.5"><span className="flex items-start gap-1"><code className="break-any">{i.value}</code><CopyButton value={i.value} /></span>
                {i.context && i.context !== i.value && <div className="mt-0.5 truncate font-mono text-[11px] text-dim" title={i.context}>{i.context}</div>}</td>
              <td className="px-3 py-1.5 text-muted">{i.type}</td>
              <td className="px-3 py-1.5">{i.common ? <Badge>common reference</Badge> : <Badge tone="warn">notable</Badge>} {i.occurrences > 1 && <span className="text-[11px] text-dim">×{i.occurrences}</span>}</td>
              <td className="px-3 py-1.5">{i.evidence_ref ? <Link className="font-mono text-[12px] text-accent" to={`/analysis/${i.analysis_id}/evidence#${i.evidence_ref}`}>{i.evidence_ref}</Link> : "—"}</td>
              {showAnalysis && <td className="px-3 py-1.5"><Link className="text-accent" to={`/analysis/${i.analysis_id}/iocs`}>{i.analysis_name}</Link></td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function IocsPage() {
  const { a, completed } = useAnalysis();
  const { data, loading } = useAsync(() => (completed ? api.iocs(a.id) : Promise.resolve([])), [a.id, completed]);
  const [tab, setTab] = useState("urls");
  const [q, setQ] = useState("");
  const [hideCommon, setHideCommon] = useState(true);
  const [defang, setDefang] = useState(true);
  const all = useMemo(() => {
    const hashes: IOC[] = a.artifacts.filter((x) => x.sha256).map((x) => ({
      type: "hash", value: x.sha256!, normalized: x.sha256!, common: false, source: "hash_engine", artifact_id: x.id, offset: null,
      occurrences: 1, evidence_ref: null, context: `SHA256 of ${x.name}`, analysis_id: a.id, analysis_name: a.name,
    }));
    return [...hashes, ...(data || [])];
  }, [data, a]);
  if (!completed) return <NotReady />;
  if (loading && !data) return <Spinner />;
  const t = IOC_TABS.find((x) => x.id === tab)!;
  const items = all.filter((i) => t.types.includes(i.type) && (!hideCommon || !i.common) && (!q || i.value.toLowerCase().includes(q.toLowerCase())));
  return (
    <Card pad={false}>
      <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter" className="w-60" />
        <label className="flex items-center gap-1.5 text-[12px] text-muted"><input type="checkbox" checked={hideCommon} onChange={(e) => setHideCommon(e.target.checked)} /> hide common references</label>
        <div className="ml-auto flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-[12px] text-muted"><input type="checkbox" checked={defang} onChange={(e) => setDefang(e.target.checked)} /> defang</label>
          {["txt", "csv", "json-download"].map((f) => (
            <Button key={f} onClick={() => download(urls.iocs(a.id, f, defang))}><Download className="h-4 w-4" /> {f.replace("-download", "").toUpperCase()}</Button>
          ))}
          <Button disabled title="Planned">STIX (future)</Button>
        </div>
      </div>
      <Tabs className="px-3" value={tab} onChange={setTab}
        tabs={IOC_TABS.map((x) => ({ id: x.id, label: x.label, count: all.filter((i) => x.types.includes(i.type) && (!hideCommon || !i.common)).length }))} />
      <IocTable items={items} />
    </Card>
  );
}
