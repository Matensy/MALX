import { Bug, FileCode2, FolderArchive, KeyRound, ShieldCheck, Sparkles, UploadCloud, X } from "lucide-react";
import { type DragEvent, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { uploadAnalysis } from "../api/client";
import { Bar, Button, Card, cx, ErrorBox, Input } from "../components/ui";
import { bytes } from "../lib/format";

const MODES = [
  { id: "auto", label: "Automatic", icon: Sparkles, desc: "Malware analysis always; application security when a project/source tree is detected." },
  { id: "malware", label: "Malware analysis", icon: Bug, desc: "“What does this file do?” Static structure, strings, IOCs, YARA, heuristics, reverse engineering." },
  { id: "appsec", label: "Application security", icon: FileCode2, desc: "“Where can this application fail?” Code weaknesses, secrets, dependencies, attack surface." },
];

export default function NewAnalysis() {
  const nav = useNavigate();
  const [files, setFiles] = useState<File[]>([]);
  const [mode, setMode] = useState("auto");
  const [password, setPassword] = useState("");
  const [notes, setNotes] = useState("");
  const [name, setName] = useState("");
  const [drag, setDrag] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const add = (list: FileList | null) => list && setFiles((f) => [...f, ...Array.from(list)]);
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDrag(false);
    add(e.dataTransfer.files);
  };
  const submit = async () => {
    if (!files.length) return;
    setError(null);
    setProgress(0);
    try {
      const res = await uploadAnalysis(files, { mode, password: password || undefined, notes: notes || undefined, name: name || undefined }, setProgress);
      setPassword("");
      nav(`/analysis/${res.id}`);
    } catch (e: any) {
      setError(e.message || "upload failed");
      setProgress(null);
    }
  };
  const total = files.reduce((n, f) => n + f.size, 0);

  return (
    <div className="mx-auto max-w-5xl space-y-5 p-6">
      <div>
        <h1 className="text-2xl font-bold">New analysis</h1>
        <p className="text-[13px] text-muted">Files go straight into quarantine under an internal name, are parsed read-only by an isolated worker, and are never executed or opened by any application.</p>
      </div>

      <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={onDrop}
        onClick={() => input.current?.click()}
        className={cx("grid-bg flex cursor-pointer flex-col items-center justify-center gap-3 rounded-2xl border-2 border-dashed p-10 text-center transition",
          drag ? "border-accent bg-accent/5" : "border-line2 bg-panel hover:border-accent/50")}>
        <UploadCloud className="h-10 w-10 text-accent" />
        <div className="text-[15px] font-semibold">Drop files here or click to choose</div>
        <div className="max-w-xl text-[12px] text-muted">Executables (PE/ELF/Mach-O), libraries, scripts, documents (PDF/Office/RTF), APK/JAR/DEX, archives (ZIP/TAR/7Z/GZ — extracted safely and recursively), project source trees.</div>
        <input ref={input} type="file" multiple hidden onChange={(e) => add(e.target.files)} />
      </div>

      {files.length > 0 && (
        <Card title={`${files.length} file(s) · ${bytes(total)}`} actions={<Button variant="ghost" onClick={() => setFiles([])}>Clear</Button>}>
          <ul className="divide-y divide-line">
            {files.map((f, i) => (
              <li key={i} className="flex items-center gap-3 py-2 text-[13px]">
                <FolderArchive className="h-4 w-4 text-muted" />
                <span className="min-w-0 flex-1 truncate font-mono">{f.name}</span>
                <span className="text-muted">{bytes(f.size)}</span>
                <button className="text-dim hover:text-sev-critical" onClick={() => setFiles(files.filter((_, j) => j !== i))}><X className="h-4 w-4" /></button>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <div className="grid gap-3 md:grid-cols-3">
        {MODES.map((m) => (
          <button key={m.id} type="button" onClick={() => setMode(m.id)}
            className={cx("rounded-xl border p-4 text-left transition", mode === m.id ? "border-accent/60 bg-accent/10" : "border-line bg-panel hover:border-line2")}>
            <div className="flex items-center gap-2 font-semibold"><m.icon className="h-4 w-4 text-accent" /> {m.label}</div>
            <div className="mt-1 text-[12px] text-muted">{m.desc}</div>
          </button>
        ))}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><KeyRound className="h-4 w-4" /> Archive password</span>}>
          <Input type="password" autoComplete="off" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Optional — e.g. infected" className="w-full" />
          <p className="mt-2 text-[12px] text-muted">Used only to extract encrypted archives. Never logged, stored, sent to reports or shown again. If empty, common sample-sharing passwords are tried.</p>
        </Card>
        <Card title="Case details">
          <div className="space-y-2">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Investigation name (optional)" className="w-full" />
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Notes (optional)" rows={2}
              className="w-full rounded-lg border border-line2 bg-panel2 px-3 py-1.5 text-[13px] outline-none placeholder:text-dim focus:border-accent/60" />
          </div>
        </Card>
      </div>

      <ErrorBox error={error} />
      <div className="flex items-center gap-4">
        <Button variant="primary" disabled={!files.length || progress !== null} onClick={submit} className="px-6 py-2 text-[14px]">
          <ShieldCheck className="h-4 w-4" /> Analyze
        </Button>
        {progress !== null && <div className="w-64"><div className="mb-1 text-[12px] text-muted">Uploading to quarantine… {progress}%</div><Bar value={progress} color="#38bdf8" /></div>}
      </div>
    </div>
  );
}
