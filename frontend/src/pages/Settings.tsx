import { CheckCircle2, Lock, ShieldAlert, WifiOff, XCircle } from "lucide-react";
import { api } from "../api/client";
import { Badge, Card, ErrorBox, KV, Spinner, Table } from "../components/ui";
import { bytes } from "../lib/format";
import { useAsync } from "../lib/hooks";

const SIZE_KEYS = new Set(["max_upload_size", "max_archive_size", "max_extracted_size", "max_entry_size", "max_memory_per_worker", "max_deep_scan_size", "max_fuzzy_hash_size"]);

export default function SettingsPage() {
  const { data: s, error } = useAsync(() => api.system(), []);
  const rules = useAsync(() => api.rules(), []);
  if (error) return <div className="p-6"><ErrorBox error={error} /></div>;
  if (!s) return <Spinner />;
  const ok = (v: boolean) => (v ? <CheckCircle2 className="h-4 w-4 text-ok" /> : <XCircle className="h-4 w-4 text-dim" />);
  return (
    <div className="mx-auto max-w-6xl space-y-4 p-6">
      <h1 className="text-2xl font-bold">Settings & system</h1>
      <div className="grid gap-3 md:grid-cols-3">
        <Card><div className="flex items-center gap-2 font-bold text-ok"><Lock className="h-5 w-5" /> {s.privacy}</div><p className="mt-1 text-[12px] text-muted">Nothing is uploaded to external services. The core works fully offline.</p></Card>
        <Card><div className="flex items-center gap-2 font-bold"><WifiOff className="h-5 w-5 text-muted" /> External integrations: {s.external_integrations}</div><p className="mt-1 text-[12px] text-muted">Optional, explicit and configurable (integrations.external_enabled).</p></Card>
        <Card><div className="flex items-center gap-2 font-bold text-sev-high"><ShieldAlert className="h-5 w-5" /> No execution</div><p className="mt-1 text-[12px] text-muted">{s.execution_policy}</p></Card>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Resource limits (malx.yaml / MALX_LIMITS__*)">
          <KV rows={Object.entries(s.limits).map(([k, v]) => [k, SIZE_KEYS.has(k) ? `${bytes(v)} (${v})` : k === "max_analysis_time" ? `${v} s` : String(v)])} />
        </Card>
        <div className="space-y-4">
          <Card title="Analysis engines">
            <Table head={["Engine", "Status", "Details"]} rows={Object.entries(s.engines).map(([k, v]: [string, any]) => [k, ok(v.available), <span className="text-[12px] text-muted">{v.version || v.implementation || ""}{v.rules ? ` · ${v.rules} rules` : ""}</span>])} />
          </Card>
          <Card title="Workers">
            <KV rows={[["Mode", s.workers.mode], ["Concurrency", s.workers.max_concurrent_analyses], ["Active", s.workers.active.length], ["Queued", s.workers.queued], ["Retain extracted", String(s.workers.retain_extracted)]]} />
          </Card>
        </div>
      </div>
      <Card title="Reverse-engineering integrations (used only when installed and enabled)" pad={false}>
        <Table head={["Tool", "Available", "Enabled", "Version", "Purpose"]} rows={s.tools.map((t) => [<code>{t.name}</code>, ok(t.available), ok(t.enabled), <span className="text-[12px] text-muted">{t.version || "—"}</span>, <span className="text-[12px]">{t.purpose}</span>])} />
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Rule packs (declarative YAML / YARA)">
          <KV rows={Object.entries(s.rules).filter(([k]) => k !== "errors").map(([k, v]) => [k.replace(/_/g, " "), String(v)])} />
          {s.rules.errors?.length > 0 && <ErrorBox error={s.rules.errors.join("; ")} />}
          <KV className="mt-3" rows={[["Advisory DB", `${s.advisories.advisories} advisories / ${s.advisories.packages} packages`], ["Directory", <code className="text-[12px]">{s.advisories.directory}</code>]]} />
        </Card>
        <Card title="Storage">
          <KV rows={[["Root", <code className="text-[12px]">{s.storage.root}</code>], ...Object.entries(s.storage.usage_bytes).map(([k, v]) => [k, bytes(v)] as [string, string]),
            ["Database", s.database], ["Version", `MALX ${s.version} · Python ${s.python}`]]} />
        </Card>
      </div>
      {rules.data && (
        <Card title={`Heuristic rules (${rules.data.heuristics.length})`} pad={false}>
          <div className="max-h-96 overflow-auto">
            <Table head={["ID", "Name", "Category", "Severity", "MITRE"]} rows={rules.data.heuristics.map((r: any) => [<code>{r.id}</code>, r.name, r.category, <Badge>{r.severity}</Badge>, <span className="font-mono text-[11px]">{r.mitre.join(", ")}</span>])} />
          </div>
        </Card>
      )}
    </div>
  );
}
