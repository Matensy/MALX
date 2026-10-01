import { Activity, FilePlus2, Globe2, LayoutDashboard, Lock, Search, Settings, ShieldAlert, WifiOff } from "lucide-react";
import { type FormEvent, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { cx } from "./ui";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/analysis/new", label: "New analysis", icon: FilePlus2 },
  { to: "/iocs", label: "IOC Center", icon: Globe2 },
  { to: "/search", label: "Search", icon: Search },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden>
      <rect width="64" height="64" rx="14" fill="#0f1a2a" />
      <path d="M14 46V18l18 16 18-16v28" fill="none" stroke="#38bdf8" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="32" cy="34" r="4" fill="#f43f5e" />
    </svg>
  );
}

export default function Layout() {
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (q.trim().length >= 2) nav(`/search?q=${encodeURIComponent(q.trim())}`);
  };
  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-line bg-panel">
        <div className="flex items-center gap-2.5 px-4 py-4">
          <Logo className="h-8 w-8" />
          <div>
            <div className="text-[17px] font-extrabold tracking-[0.18em]">MALX</div>
            <div className="text-[10px] uppercase tracking-wider text-dim">Security Workbench</div>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5 px-2">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to !== "/analysis/new"}
              className={({ isActive }) => cx("flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium",
                isActive ? "bg-accent/10 text-accent" : "text-muted hover:bg-panel2 hover:text-text")}>
              <Icon className="h-4 w-4" /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="m-3 space-y-2 rounded-lg border border-line bg-panel2 p-3 text-[11px] text-muted">
          <div className="flex items-center gap-2 font-semibold text-ok"><Lock className="h-3.5 w-3.5" /> YOUR FILES STAY LOCAL</div>
          <div className="flex items-center gap-2"><WifiOff className="h-3.5 w-3.5" /> External integrations: DISABLED</div>
          <div className="flex items-center gap-2"><ShieldAlert className="h-3.5 w-3.5" /> Samples are never executed</div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-line bg-panel/80 px-5 py-2.5 backdrop-blur">
          <form onSubmit={submit} className="relative max-w-xl flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-dim" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search MALX — SHA256, filename, URL, domain, IP, API, string, finding, MITRE…"
              className="w-full rounded-lg border border-line2 bg-panel2 py-2 pl-9 pr-3 text-[13px] outline-none placeholder:text-dim focus:border-accent/60" />
          </form>
          <div className="ml-auto flex items-center gap-2 text-[12px] text-muted">
            <Activity className="h-4 w-4 text-ok" /> static analysis · evidence-first
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
