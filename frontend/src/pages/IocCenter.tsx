import { Download } from "lucide-react";
import { useMemo, useState } from "react";
import { api, urls } from "../api/client";
import { Button, Card, Input, Spinner, Tabs } from "../components/ui";
import { download } from "../lib/format";
import { useAsync, useDebounced } from "../lib/hooks";
import { IOC_TABS, IocTable } from "./analysis/Iocs";

export default function IocCenter() {
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [common, setCommon] = useState(false);
  const [tab, setTab] = useState("domains");
  const { data, loading } = useAsync(() => api.globalIocs({ q: dq || undefined, include_common: common }), [dq, common]);
  const items = useMemo(() => data || [], [data]);
  const t = IOC_TABS.find((x) => x.id === tab)!;
  return (
    <div className="mx-auto max-w-7xl space-y-4 p-6">
      <div>
        <h1 className="text-2xl font-bold">IOC Center</h1>
        <p className="text-[13px] text-muted">Indicators extracted statically across every analysis. Hashes, domains, IPs, URLs, files, registry, mutexes, e-mails.</p>
      </div>
      <Card pad={false}>
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search indicators" className="w-72" />
          <label className="flex items-center gap-1.5 text-[12px] text-muted"><input type="checkbox" checked={common} onChange={(e) => setCommon(e.target.checked)} /> include common references</label>
          <div className="ml-auto flex gap-2">
            {["txt", "csv", "json-download"].map((f) => <Button key={f} onClick={() => download(urls.globalIocs(f, true))}><Download className="h-4 w-4" /> {f.replace("-download", "").toUpperCase()}</Button>)}
            <Button disabled>STIX (future)</Button>
          </div>
        </div>
        <Tabs className="px-3" value={tab} onChange={setTab} tabs={IOC_TABS.filter((x) => x.id !== "hashes").map((x) => ({ id: x.id, label: x.label, count: items.filter((i) => x.types.includes(i.type)).length }))} />
        {loading && !data ? <Spinner /> : <IocTable items={items.filter((i) => t.types.includes(i.type))} showAnalysis />}
      </Card>
    </div>
  );
}
