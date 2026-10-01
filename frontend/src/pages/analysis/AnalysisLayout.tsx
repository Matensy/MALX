import { Ban, CheckCircle2, Circle, Loader2, RotateCcw, Trash2, XCircle } from "lucide-react";
import { NavLink, Outlet, useNavigate, useParams } from "react-router-dom";
import { api } from "../../api/client";
import { Badge, Button, ClassBadge, cx, ErrorBox, Mono, RiskGauge, Spinner } from "../../components/ui";
import { bytes, dt, ms, RUNNING, STAGES } from "../../lib/format";
import { useAsync, useInterval } from "../../lib/hooks";
import { AnalysisContext } from "./context";

const TABS = [
  { to: "", label: "Overview" },
  { to: "static", label: "Static" },
  { to: "reverse", label: "Reverse" },
  { to: "security", label: "Security" },
  { to: "findings", label: "Findings" },
  { to: "evidence", label: "Evidence" },
  { to: "graph", label: "Graph" },
  { to: "timeline", label: "Timeline" },
  { to: "iocs", label: "IOCs" },
  { to: "mitre", label: "MITRE" },
  { to: "board", label: "Board" },
  { to: "report", label: "Report" },
];

function Pipeline({ status, progress, detail }: { status: string; progress: number; detail: string | null }) {
  const idx = STAGES.indexOf(status);
  const failed = status === "FAILED" || status === "CANCELLED";
  return (
    <div className="rounded-xl border border-line bg-panel p-4">
      <div className="flex flex-wrap items-center gap-1">
        {STAGES.map((s, i) => {
          const done = !failed && (idx > i || status === "COMPLETED");
          const active = !failed && idx === i && status !== "COMPLETED";
          return (
            <div key={s} className="flex items-center gap-1">
              <div className={cx("flex items-center gap-1.5 rounded-md px-2 py-1 text-[11px] font-semibold tracking-wide",
                done ? "text-ok" : active ? "bg-accent/10 text-accent" : "text-dim")}>
                {done ? <CheckCircle2 className="h-3.5 w-3.5" /> : active ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Circle className="h-3.5 w-3.5" />}
                {s}
              </div>
              {i < STAGES.length - 1 && <div className={cx("h-px w-4", done ? "bg-ok/50" : "bg-line2")} />}
            </div>
          );
        })}
        {failed && <Badge tone="danger"><XCircle className="h-3.5 w-3.5" /> {status}</Badge>}
      </div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-line">
        <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${progress}%` }} />
      </div>
      {detail && <div className="mt-2 truncate font-mono text-[11px] text-muted">{detail}</div>}
    </div>
  );
}

export default function AnalysisLayout() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const { data: a, error, reload } = useAsync(() => api.get(id), [id]);
  const running = a ? RUNNING.has(a.status) : false;
  useInterval(reload, running ? 1000 : null);

  if (error) return <div className="p-6"><ErrorBox error={error} /></div>;
  if (!a) return <Spinner />;
  const root = a.artifacts.find((x) => x.parent_id === null);
  const completed = a.status === "COMPLETED";

  return (
    <AnalysisContext.Provider value={{ a, reload, completed }}>
      <div className="mx-auto max-w-[1500px] space-y-4 p-6">
        <div className="flex flex-wrap items-start gap-5">
          <RiskGauge score={a.risk_score} />
          <div className="min-w-0 flex-1 space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="truncate text-xl font-bold">{a.name}</h1>
              {a.classification && <ClassBadge value={a.classification} large />}
              <Badge>{a.mode}</Badge>
            </div>
            <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[12px] text-muted">
              <span className="flex items-center gap-1">SHA256 <Mono copy>{a.sha256}</Mono></span>
            </div>
            <div className="flex flex-wrap gap-x-5 gap-y-1 text-[12px] text-muted">
              <span>Type: <span className="text-text">{a.main_type || "—"}</span></span>
              <span>Size: <span className="text-text">{bytes(root?.size)}</span></span>
              {root?.architecture && <span>Arch: <span className="text-text">{root.architecture}</span></span>}
              <span>Artifacts: <span className="text-text">{a.artifact_count}</span></span>
              <span>First analyzed: <span className="text-text">{dt(a.created_at)}</span></span>
              <span>Duration: <span className="text-text">{ms(a.duration_ms)}</span></span>
            </div>
          </div>
          <div className="flex gap-2">
            {running && <Button variant="danger" onClick={async () => { await api.cancel(a.id); reload(); }}><Ban className="h-4 w-4" /> Cancel</Button>}
            {!running && <Button onClick={async () => { await api.reanalyze(a.id); reload(); }} title="Re-run the analysis on the quarantined files"><RotateCcw className="h-4 w-4" /> Re-analyze</Button>}
            {!running && (
              <Button variant="ghost" title="Delete analysis and purge files"
                onClick={async () => {
                  if (confirm("Delete this analysis and purge all stored files?")) {
                    await api.remove(a.id);
                    nav("/dashboard");
                  }
                }}><Trash2 className="h-4 w-4" /></Button>
            )}
          </div>
        </div>

        {(running || a.status === "FAILED" || a.status === "CANCELLED") && <Pipeline status={a.status} progress={a.progress} detail={a.error || a.stage_detail} />}

        <nav className="flex flex-wrap gap-1 border-b border-line">
          {TABS.map((t) => (
            <NavLink key={t.to} to={t.to} end={t.to === ""}
              className={({ isActive }) => cx("-mb-px border-b-2 px-3 py-2 text-[13px] font-medium",
                isActive ? "border-accent text-text" : "border-transparent text-muted hover:text-text",
                t.to === "security" && !a.has_appsec && "opacity-60")}>
              {t.label}
              {t.to === "findings" && a.finding_count > 0 && <span className="ml-1.5 rounded bg-panel3 px-1.5 text-[11px] text-muted">{a.finding_count}</span>}
            </NavLink>
          ))}
        </nav>
        <Outlet />
      </div>
    </AnalysisContext.Provider>
  );
}
