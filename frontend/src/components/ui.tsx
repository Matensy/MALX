import { Check, ChevronDown, ChevronRight, Copy, Loader2 } from "lucide-react";
import { type ReactNode, useState } from "react";
import type { Classification, Severity } from "../api/types";
import { CLASS_META, riskColor, SEV_CLASS } from "../lib/format";

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

export function Card({ children, className, title, actions, pad = true }: {
  children: ReactNode; className?: string; title?: ReactNode; actions?: ReactNode; pad?: boolean;
}) {
  return (
    <section className={cx("rounded-xl border border-line bg-panel", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h3 className="text-[13px] font-semibold uppercase tracking-wider text-muted">{title}</h3>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={pad ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cx("inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10.5px] font-bold uppercase tracking-wide", SEV_CLASS[severity], className)}>
      {severity}
    </span>
  );
}

export function ClassBadge({ value, large }: { value: Classification | null | undefined; large?: boolean }) {
  const meta = CLASS_META[value || "UNKNOWN"];
  return (
    <span className={cx("inline-flex items-center rounded-lg border font-bold uppercase tracking-wide", meta.cls,
      large ? "px-3 py-1.5 text-sm" : "px-2 py-0.5 text-[10.5px]")}>
      {meta.label}
    </span>
  );
}

export function Badge({ children, className, tone = "default", title }: { children: ReactNode; className?: string; tone?: "default" | "accent" | "warn" | "ok" | "danger"; title?: string }) {
  const tones = {
    default: "border-line2 bg-panel3 text-muted",
    accent: "border-accent/40 bg-accent/10 text-accent",
    warn: "border-sev-high/40 bg-sev-high/10 text-sev-high",
    ok: "border-ok/40 bg-ok/10 text-ok",
    danger: "border-sev-critical/40 bg-sev-critical/10 text-sev-critical",
  };
  return <span title={title} className={cx("inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium", tones[tone], className)}>{children}</span>;
}

export function Button({ children, onClick, variant = "default", className, disabled, type = "button", title }: {
  children: ReactNode; onClick?: () => void; variant?: "default" | "primary" | "ghost" | "danger"; className?: string;
  disabled?: boolean; type?: "button" | "submit"; title?: string;
}) {
  const v = {
    default: "border-line2 bg-panel2 hover:bg-panel3 text-text",
    primary: "border-accent/60 bg-accent/15 hover:bg-accent/25 text-accent",
    ghost: "border-transparent hover:bg-panel3 text-muted hover:text-text",
    danger: "border-sev-critical/50 bg-sev-critical/10 hover:bg-sev-critical/20 text-sev-critical",
  };
  return (
    <button type={type} title={title} disabled={disabled} onClick={onClick}
      className={cx("inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[13px] font-medium transition disabled:opacity-40", v[variant], className)}>
      {children}
    </button>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 text-muted">
      <Loader2 className="h-4 w-4 animate-spin" /> {label || "Loading…"}
    </div>
  );
}

export function Empty({ children, icon }: { children: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-line p-8 text-center text-muted">
      {icon}
      <div className="max-w-md text-[13px]">{children}</div>
    </div>
  );
}

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-3 text-sm text-sev-critical">{error}</div>;
}

export function CopyButton({ value, className }: { value: string; className?: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      type="button"
      title="Copy"
      className={cx("inline-flex h-6 w-6 items-center justify-center rounded text-dim hover:bg-panel3 hover:text-text", className)}
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(value).then(() => {
          setOk(true);
          setTimeout(() => setOk(false), 1200);
        });
      }}
    >
      {ok ? <Check className="h-3.5 w-3.5 text-ok" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

export function Mono({ children, className, copy }: { children: string | null | undefined; className?: string; copy?: boolean }) {
  if (!children) return <span className="text-dim">—</span>;
  return (
    <span className={cx("inline-flex max-w-full items-center gap-1", className)}>
      <code className="break-any text-[12px] text-text/90">{children}</code>
      {copy && <CopyButton value={children} />}
    </span>
  );
}

export function KV({ rows, className }: { rows: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cx("grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-1.5 text-[13px]", className)}>
      {rows.map(([k, v], i) => (
        <div className="contents" key={i}>
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-any">{v ?? <span className="text-dim">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange, className }: {
  tabs: { id: T; label: ReactNode; count?: number }[]; value: T; onChange: (v: T) => void; className?: string;
}) {
  return (
    <div className={cx("flex flex-wrap gap-1 border-b border-line", className)}>
      {tabs.map((t) => (
        <button key={t.id} type="button" onClick={() => onChange(t.id)}
          className={cx("-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-[13px] font-medium",
            value === t.id ? "border-accent text-text" : "border-transparent text-muted hover:text-text")}>
          {t.label}
          {t.count !== undefined && <span className="rounded bg-panel3 px-1.5 text-[11px] text-muted">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Bar({ value, color, className }: { value: number; color?: string; className?: string }) {
  return (
    <div className={cx("h-1.5 w-full overflow-hidden rounded-full bg-line", className)}>
      <div className="h-full rounded-full transition-all" style={{ width: `${Math.max(0, Math.min(100, value))}%`, background: color || riskColor(value) }} />
    </div>
  );
}

export function RiskGauge({ score, size = 112 }: { score: number | null | undefined; size?: number }) {
  const s = score ?? 0;
  const r = size / 2 - 9;
  const c = 2 * Math.PI * r;
  const arc = c * 0.75;
  const color = riskColor(s);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Risk ${s}`}>
      <g transform={`rotate(135 ${size / 2} ${size / 2})`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1d2a3a" strokeWidth="9" strokeDasharray={`${arc} ${c}`} strokeLinecap="round" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="9" strokeDasharray={`${(arc * s) / 100} ${c}`} strokeLinecap="round" />
      </g>
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" fill="#d8e3ee" fontSize={size / 4} fontWeight="700">{score ?? "—"}</text>
      <text x="50%" y={size * 0.74} textAnchor="middle" fill="#7d91a7" fontSize={10} letterSpacing="1.5">RISK</text>
    </svg>
  );
}

export function Collapsible({ title, children, defaultOpen = false, right }: { title: ReactNode; children: ReactNode; defaultOpen?: boolean; right?: ReactNode }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-line bg-panel2">
      <button type="button" onClick={() => setOpen(!open)} className="flex w-full items-center gap-2 px-3 py-2 text-left">
        {open ? <ChevronDown className="h-4 w-4 text-muted" /> : <ChevronRight className="h-4 w-4 text-muted" />}
        <div className="min-w-0 flex-1">{title}</div>
        {right}
      </button>
      {open && <div className="border-t border-line p-3">{children}</div>}
    </div>
  );
}

export function Table({ head, rows, className, empty }: { head: ReactNode[]; rows: ReactNode[][]; className?: string; empty?: string }) {
  return (
    <div className={cx("overflow-x-auto", className)}>
      <table className="w-full border-collapse text-[13px]">
        <thead>
          <tr>{head.map((h, i) => <th key={i} className="whitespace-nowrap border-b border-line px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-muted">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr><td colSpan={head.length} className="px-3 py-6 text-center text-muted">{empty || "Nothing here."}</td></tr>
          )}
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-line/60 hover:bg-panel2/70">
              {r.map((c, j) => <td key={j} className="px-3 py-2 align-top">{c}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx("rounded-lg border border-line2 bg-panel2 px-3 py-1.5 text-[13px] text-text outline-none placeholder:text-dim focus:border-accent/60", props.className)} />;
}

export function Select({ value, onChange, options, className }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; className?: string }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}
      className={cx("rounded-lg border border-line2 bg-panel2 px-2 py-1.5 text-[13px] text-text outline-none focus:border-accent/60", className)}>
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}

export function Stat({ label, value, sub, color }: { label: string; value: ReactNode; sub?: ReactNode; color?: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel p-4">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted">{label}</div>
      <div className="mt-1 text-2xl font-bold" style={color ? { color } : undefined}>{value}</div>
      {sub && <div className="mt-0.5 text-[12px] text-muted">{sub}</div>}
    </div>
  );
}
