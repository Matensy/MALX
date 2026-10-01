import { AlertTriangle } from "lucide-react";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import type { ArtifactDetail, Evidence } from "../../api/types";
import EntropyChart from "../../components/EntropyChart";
import HexView from "../../components/HexView";
import JsonTree from "../../components/JsonTree";
import { Badge, Bar, Card, Collapsible, cx, Empty, Input, KV, Mono, SeverityBadge, Spinner, Table, Tabs } from "../../components/ui";
import { bytes, dt } from "../../lib/format";
import { useAsync, useDebounced } from "../../lib/hooks";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

const CLASSES = ["", "HIGH_RISK", "SUSPICIOUS", "INTERESTING", "NORMAL"] as const;
const CLASS_TONE: Record<string, string> = { HIGH_RISK: "text-sev-critical", SUSPICIOUS: "text-sev-high", INTERESTING: "text-sev-low", NORMAL: "text-muted" };

function Perm({ p }: { p: string }) {
  return (
    <span className="font-mono text-[12px]">
      {p.split("").map((c, i) => <span key={i} className={c === "-" ? "text-dim" : c === "x" && p.includes("w") ? "font-bold text-sev-critical" : "text-text"}>{c}</span>)}
    </span>
  );
}

function StringsExplorer({ aid, artifactId }: { aid: string; artifactId: string }) {
  const [cls, setCls] = useState<string>("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const dq = useDebounced(q);
  const { data, loading } = useAsync(() => api.strings(aid, artifactId, { classification: cls || undefined, q: dq || undefined, offset: page * 200, limit: 200 }), [aid, artifactId, cls, dq, page]);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tabs value={cls} onChange={(v) => { setCls(v); setPage(0); }}
          tabs={CLASSES.map((c) => ({ id: c, label: c || "All", count: c ? data?.counts?.[c] ?? 0 : undefined }))} />
        <Input value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} placeholder="Search strings" className="ml-auto w-64" />
      </div>
      {loading && !data ? <Spinner /> : (
        <>
          <div className="max-h-[560px] overflow-auto rounded-lg border border-line">
            <table className="w-full text-[12px]">
              <thead className="sticky top-0 bg-panel2"><tr className="text-left text-[11px] uppercase tracking-wider text-muted">
                <th className="px-3 py-1.5">Offset</th><th className="px-3 py-1.5">Enc</th><th className="px-3 py-1.5">Class</th><th className="px-3 py-1.5">Value</th><th className="px-3 py-1.5">Tags</th></tr></thead>
              <tbody>
                {data?.items.map((s, i) => (
                  <tr key={i} className="border-t border-line/60 align-top">
                    <td className="px-3 py-1 font-mono text-dim">0x{s.offset.toString(16)}</td>
                    <td className="px-3 py-1 text-dim">{s.encoding}</td>
                    <td className={cx("px-3 py-1 text-[11px] font-semibold", CLASS_TONE[s.classification])}>{s.classification}</td>
                    <td className="break-any px-3 py-1 font-mono">{s.value}</td>
                    <td className="px-3 py-1">{s.tags.slice(0, 4).map((t: string) => <Badge key={t} className="mr-1">{t}</Badge>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center gap-3 text-[12px] text-muted">
            <span>{data?.total ?? 0} stored strings (most relevant first; full scan is used for detection)</span>
            <button disabled={page === 0} className="ml-auto disabled:opacity-30" onClick={() => setPage(page - 1)}>← prev</button>
            <span>page {page + 1}</span>
            <button disabled={!data || (page + 1) * 200 >= data.total} className="disabled:opacity-30" onClick={() => setPage(page + 1)}>next →</button>
          </div>
        </>
      )}
    </div>
  );
}

function PEView({ pe, suspicious }: { pe: any; suspicious: Set<string> }) {
  if (pe.error) return <Empty>PE parsing failed: {pe.error}</Empty>;
  const h = pe.headers;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Headers">
          <KV rows={[
            ["Machine / bits", `${h.machine} · ${h.bits}-bit`], ["Subsystem", String(h.subsystem)], ["Image base", <Mono>{h.image_base}</Mono>],
            ["Entry point", <span><Mono>{h.entry_point_va}</Mono> <span className="text-muted">in {pe.entry_point_section || "no section"}</span></span>],
            ["Compile time", <span>{h.timestamp_iso || h.timestamp} {h.timestamp_anomaly && <Badge tone="warn">{h.timestamp_anomaly}</Badge>}</span>],
            ["Linker / OS", `${h.linker_version} / ${h.os_version}`], ["Characteristics", h.characteristics.join(", ")],
            ["DLL characteristics", h.dll_characteristics.join(", ") || "—"],
            ["Checksum", h.checksum_stored ? `${h.checksum_stored} ${h.checksum_valid === false ? "(mismatch)" : h.checksum_valid ? "(valid)" : ""}` : "0"],
            ["Imphash", <Mono copy>{pe.imphash}</Mono>], ["PDB", <Mono>{pe.pdb_path}</Mono>],
          ]} />
        </Card>
        <Card title="Signature, packers & mitigations">
          <KV rows={[
            ["Authenticode", pe.signature?.present ? <span>present <span className="text-muted">({pe.signature.certificate_type}) — not cryptographically verified</span></span> : "not signed"],
            ["Signer", pe.signature?.signer || "—"],
            ["Packers / tooling", pe.packers?.length ? pe.packers.map((p: any) => <Badge key={p.name} tone={p.kind === "packer" || p.kind === "protector" ? "warn" : "default"} className="mr-1">{p.name} · {p.kind}</Badge>) : "none detected"],
            ["ASLR / DEP / CFG", ["aslr", "dep", "cfg"].map((k) => `${k.toUpperCase()}:${pe.mitigations?.[k] ? "on" : "off"}`).join("  ")],
            [".NET", pe.dotnet ? `${pe.dotnet.runtime_version || "yes"} · ${pe.dotnet.member_name_count ?? 0} members, ${pe.dotnet.user_string_count ?? 0} user strings` : "no"],
            ["Overlay", pe.overlay ? `${bytes(pe.overlay.size)} at 0x${pe.overlay.offset.toString(16)} · H=${pe.overlay.entropy} ${pe.overlay.magic || ""}` : "none"],
            ["TLS callbacks", pe.tls?.callbacks?.length ? pe.tls.callbacks.join(", ") : "none"],
            ["Requested level", pe.requested_execution_level || "—"],
          ]} />
          {pe.signature?.certificates?.length > 0 && (
            <div className="mt-3 space-y-1 text-[12px]">
              {pe.signature.certificates.map((c: any, i: number) => (
                <div key={i} className="rounded border border-line bg-panel2 p-2"><div className="break-any">{c.subject}</div>
                  <div className="text-muted">issuer {c.issuer} · {dt(c.not_before)} → {dt(c.not_after)} {c.self_signed && <Badge tone="warn">self-signed</Badge>} {c.expired && <Badge>expired</Badge>}</div></div>
              ))}
            </div>
          )}
        </Card>
      </div>
      <Card title="Sections" pad={false}>
        <Table head={["Name", "VA", "Virtual size", "Raw size", "Perms", "Entropy", ""]} rows={pe.sections.map((s: any) => [
          <Mono>{s.name || "(empty)"}</Mono>, <Mono>{s.virtual_address}</Mono>, bytes(s.virtual_size), bytes(s.raw_size), <Perm p={s.permissions} />,
          <div className="flex w-36 items-center gap-2"><span className="w-9 font-mono">{s.entropy}</span><Bar value={(s.entropy / 8) * 100} color={s.entropy >= 7.2 ? "#f43f5e" : s.entropy >= 6.5 ? "#fb923c" : "#38bdf8"} /></div>,
          s.entry_point ? <Badge tone="accent">entry</Badge> : null,
        ])} />
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={`Imports (${pe.import_count})`}>
          <div className="space-y-2">
            {pe.imports.map((imp: any) => (
              <Collapsible key={imp.dll} defaultOpen={imp.functions.some((f: string) => suspicious.has(f))}
                title={<span className="font-mono text-[13px]">{imp.dll} <span className="text-muted">({imp.functions.length})</span></span>}
                right={imp.functions.some((f: string) => suspicious.has(f)) ? <Badge tone="warn">notable</Badge> : null}>
                <div className="flex flex-wrap gap-1">
                  {imp.functions.map((f: string) => (
                    <span key={f} className={cx("rounded border px-1.5 py-0.5 font-mono text-[11.5px]", suspicious.has(f) ? "border-sev-high/50 bg-sev-high/10 text-sev-high" : "border-line text-text/80")}>{f}</span>
                  ))}
                </div>
              </Collapsible>
            ))}
            {!pe.imports.length && <Empty>No import table.</Empty>}
          </div>
        </Card>
        <div className="space-y-4">
          <Card title={`Exports (${pe.exports.length})`}>
            {pe.exports.length ? <div className="flex max-h-48 flex-wrap gap-1 overflow-auto">{pe.exports.map((e: any, i: number) => <span key={i} className="rounded border border-line px-1.5 py-0.5 font-mono text-[11.5px]">{e.name || `#${e.ordinal}`}</span>)}</div> : <div className="text-[13px] text-muted">None.</div>}
          </Card>
          <Card title={`Resources (${pe.resources.length})`} pad={false}>
            <Table head={["Type", "Name", "Size", "Entropy", "Content"]} rows={pe.resources.slice(0, 80).map((r: any) => [
              r.type, <Mono>{r.name}</Mono>, bytes(r.size), r.entropy ?? "—", r.magic ? <Badge tone={r.magic.startsWith("PE") ? "danger" : "default"}>{r.magic}</Badge> : "",
            ])} />
          </Card>
          {pe.version_info && <Card title="Version information"><KV rows={Object.entries(pe.version_info).map(([k, v]) => [k, String(v)])} /></Card>}
        </div>
      </div>
      {pe.manifest && <Collapsible title="Manifest"><pre className="max-h-72 overflow-auto whitespace-pre-wrap font-mono text-[11.5px] text-muted">{pe.manifest}</pre></Collapsible>}
      {pe.rich_header && <Collapsible title={`Rich header (${pe.rich_header.entries.length} entries)`}><JsonTree value={pe.rich_header} /></Collapsible>}
    </div>
  );
}

function ELFView({ elf }: { elf: any }) {
  if (elf.error) return <Empty>ELF parsing failed: {elf.error}</Empty>;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Header"><KV rows={Object.entries(elf.header).map(([k, v]) => [k, String(v)])} /></Card>
        <Card title="Linking & properties">
          <KV rows={[
            ["Interpreter", <Mono>{elf.interpreter}</Mono>], ["NEEDED", elf.needed.join(", ") || "—"], ["RPATH", elf.rpath.join(":") || "—"],
            ["RUNPATH", elf.runpath.join(":") || "—"], ["SONAME", elf.soname || "—"],
            ...Object.entries(elf.properties).map(([k, v]) => [k, String(v)] as [string, string]),
            ["Packers / tooling", elf.packers?.map((p: any) => p.name).join(", ") || "none"],
          ]} />
        </Card>
      </div>
      <Card title="Segments" pad={false}><Table head={["Type", "VAddr", "File size", "Mem size", "Perms"]} rows={elf.segments.map((s: any) => [s.type, <Mono>{s.vaddr}</Mono>, bytes(s.filesz), bytes(s.memsz), <Perm p={s.permissions} />])} /></Card>
      <Card title="Sections" pad={false}><Table head={["Name", "Type", "Address", "Size", "Flags", "Entropy"]} rows={elf.sections.map((s: any) => [<Mono>{s.name}</Mono>, s.type, <Mono>{s.address}</Mono>, bytes(s.size), s.flags, s.entropy ?? "—"])} /></Card>
      <Card title={`Imported symbols (${elf.imported_symbols.length})`}><div className="flex flex-wrap gap-1">{elf.imported_symbols.map((s: string) => <span key={s} className="rounded border border-line px-1.5 py-0.5 font-mono text-[11.5px]">{s}</span>)}</div></Card>
    </div>
  );
}

function APKView({ apk }: { apk: any }) {
  const m = apk.manifest || {};
  const DANGER = ["SMS", "ACCESSIBILITY", "DEVICE_ADMIN", "CALL", "CONTACTS", "RECORD_AUDIO", "SYSTEM_ALERT", "INSTALL_PACKAGES", "NOTIFICATION"];
  return (
    <div className="space-y-4">
      <Card title="Package"><KV rows={[["Package", m.package], ["Version", `${m.version_name ?? "—"} (${m.version_code ?? "—"})`], ["SDK", `min ${m.sdk?.min ?? "?"} / target ${m.sdk?.target ?? "?"}`],
        ["Application", JSON.stringify(m.application || {})], ["Native ABIs", apk.abis?.join(", ") || "—"], ["DEX files", apk.dex_files?.join(", ")],
        ["Certificates", apk.certificates?.map((c: any) => c.subject).join(" | ") || "—"]]} /></Card>
      <Card title={`Permissions (${m.permissions?.length || 0})`}>
        <div className="flex flex-wrap gap-1">{(m.permissions || []).map((p: string) => <Badge key={p} tone={DANGER.some((d) => p.includes(d)) ? "danger" : "default"}>{p.replace("android.permission.", "")}</Badge>)}</div>
      </Card>
      <Card title="Components" pad={false}>
        <Table head={["Type", "Name", "Exported", "Permission", "Actions"]} rows={(m.components || []).map((c: any) => [c.type, <Mono>{c.name}</Mono>,
          c.exported_effective ? <Badge tone="warn">exported</Badge> : "no", <Mono>{c.permission}</Mono>, <span className="text-[11px] text-muted">{(c.actions || []).join(", ")}</span>])} />
      </Card>
    </div>
  );
}

function DocumentView({ meta }: { meta: any }) {
  return (
    <div className="space-y-4">
      {meta.pdf && (
        <Card title="PDF keywords">
          <div className="flex flex-wrap gap-1.5">{Object.entries(meta.pdf.keywords).filter(([, v]) => (v as number) > 0).map(([k, v]) => (
            <Badge key={k} tone={["/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile"].includes(k) ? "warn" : "default"}>{k} {String(v)}</Badge>))}</div>
          <KV className="mt-3" rows={[["Header offset", meta.pdf.header_offset], ["%%EOF markers", meta.pdf.eof_markers], ["Trailing bytes", meta.pdf.trailing_bytes],
            ["Streams decoded", meta.pdf.streams_decoded], ["Obfuscated names", meta.pdf.obfuscated_names.join(", ") || "—"], ["Info", JSON.stringify(meta.pdf.info)]]} />
          {meta.pdf.javascript_snippets?.map((s: string, i: number) => <pre key={i} className="mt-2 max-h-48 overflow-auto rounded border border-sev-high/30 bg-bg p-2 font-mono text-[11.5px] text-sev-high/90">{s}</pre>)}
        </Card>
      )}
      {meta.ooxml && (
        <Card title="Office Open XML">
          <KV rows={[["VBA project", meta.ooxml.has_vba ? "yes" : "no"], ["XLM macro sheets", meta.ooxml.xlm_macrosheets.join(", ") || "—"],
            ["Embedded objects", meta.ooxml.embeddings.join(", ") || "—"], ["ActiveX", meta.ooxml.activex.join(", ") || "—"],
            ["Metadata", JSON.stringify(meta.ooxml.metadata)]]} />
          {meta.ooxml.external_relationships.length > 0 && <Table className="mt-3" head={["Part", "Type", "External target"]}
            rows={meta.ooxml.external_relationships.map((r: any) => [<Mono>{r.source}</Mono>, r.type, <Mono>{r.target}</Mono>])} />}
          {meta.ooxml.dde.map((d: any, i: number) => <div key={i} className="mt-2 font-mono text-[12px] text-sev-high">DDE: {d.field}</div>)}
        </Card>
      )}
      {meta.ole && (
        <Card title="OLE container">
          <KV rows={[["Streams", meta.ole.streams.length], ["Metadata", JSON.stringify(meta.ole.metadata)], ["Packager objects", meta.ole.ole10native.map((o: any) => o.label || o.path).join(", ") || "—"]]} />
          {meta.ole.vba_modules.map((m: any) => (
            <Collapsible key={m.stream} defaultOpen title={<span className="font-mono">VBA · {m.stream} ({m.size} chars) — decompressed statically, never executed</span>}>
              <pre className="max-h-96 overflow-auto font-mono text-[11.5px] text-text/90">{m.code}</pre>
            </Collapsible>
          ))}
        </Card>
      )}
      {meta.rtf && <Card title="RTF"><KV rows={Object.entries(meta.rtf).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") || "—" : String(v)])} /></Card>}
      {meta.lnk && <Card title="Windows shortcut"><KV rows={Object.entries(meta.lnk).map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)])} /></Card>}
      {meta.script && (
        <Card title={`Script (${meta.script.language})`}>
          <KV rows={[["Lines", meta.script.lines], ["Longest line", meta.script.max_line_length], ["Entropy", meta.script.entropy],
            ["Obfuscation", `${meta.script.obfuscation_score} — ${meta.script.obfuscation_reasons.join("; ") || "none"}`]]} />
          {meta.script.decoded.length > 0 && <Table className="mt-3" head={["Method", "Offset", "Result"]} rows={meta.script.decoded.map((d: any) => [d.method, d.offset,
            d.kind === "text" ? <Mono>{d.preview}</Mono> : <Badge tone="danger">binary {bytes(d.size)} magic {d.magic}</Badge>])} />}
        </Card>
      )}
      {meta.archive && (
        <Card title={`Archive (${meta.archive.format})`} pad={false}>
          <div className="px-4 pt-3 text-[12px] text-muted">{JSON.stringify(meta.archive.stats)}</div>
          <Table head={["Member", "Kind", "Size", "Ratio", "Issues", "Status"]} rows={meta.archive.members.slice(0, 400).map((m: any) => [
            <Mono>{m.name}</Mono>, m.kind, bytes(m.size), m.ratio ? `${m.ratio.toFixed(1)}:1` : "—",
            m.issues.map((i: string) => <Badge key={i} tone="danger" className="mr-1">{i}</Badge>),
            m.extracted ? <Badge tone="ok">extracted</Badge> : <span className="text-[12px] text-muted">{m.skipped_reason || "—"}</span>,
          ])} />
        </Card>
      )}
      {(meta.dex || meta.java || meta.macho) && <Card title="Bytecode / Mach-O"><JsonTree value={{ dex: meta.dex, java: meta.java, macho: meta.macho }} /></Card>}
    </div>
  );
}

function Detail({ aid, art, evidence }: { aid: string; art: ArtifactDetail; evidence: Evidence[] }) {
  const [tab, setTab] = useState<"identity" | "structure" | "strings" | "hex" | "raw">("identity");
  const mine = evidence.filter((e) => e.artifact_id === art.id);
  const suspicious = new Set(mine.filter((e) => e.type === "suspicious_import").map((e) => e.value || ""));
  const m = art.metadata;
  const i = art.identification;
  const hasStructure = m.pe || m.elf || m.apk || m.pdf || m.ooxml || m.ole || m.rtf || m.lnk || m.script || m.archive || m.dex || m.java || m.macho;
  return (
    <div className="space-y-4">
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "identity", label: "Identification & hashes" }, { id: "structure", label: "Structure" },
        { id: "strings", label: "Strings", count: art.string_count }, { id: "hex", label: "Hex" }, { id: "raw", label: "Raw metadata" },
      ]} />
      {tab === "identity" && (
        <div className="space-y-4">
          {i.extension_mismatch && (
            <div className="flex items-center gap-3 rounded-xl border border-sev-high/40 bg-sev-high/10 p-3 text-sev-high">
              <AlertTriangle className="h-5 w-5" /><div><div className="font-bold">⚠ EXTENSION MISMATCH</div><div className="text-[13px]">{i.mismatch_reason}</div></div>
            </div>
          )}
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Identification">
              <KV rows={[["Detected type", <span className="font-semibold">{i.label}</span>], ["Confidence", `${Math.round(i.confidence * 100)}%`], ["Parser used", i.parser],
                ["Extension", i.extension || "—"], ["Magic bytes", <Mono>{i.magic_hex}</Mono>], ["MIME", i.mime], ["Size", `${bytes(art.size)} (${art.size} bytes)`],
                ["Architecture", art.architecture || "—"], ["Name issues", art.name_issues.join(", ") || "none"], ["Tags", art.tags.join(", ") || "—"]]} />
            </Card>
            <Card title="Hashes (SHA-256 is the primary identifier)">
              <KV rows={Object.entries(art.hashes).map(([k, v]) => [k.toUpperCase(), <Mono copy>{v}</Mono>])} />
            </Card>
          </div>
          <Card title={`Entropy · overall ${art.entropy ?? "—"} bits/byte`}><EntropyChart values={art.entropy_profile} /></Card>
          {(art.limitations.length > 0 || art.errors.length > 0) && (
            <Card title="Limitations & parser errors">
              <ul className="space-y-1 text-[12px] text-muted">{[...art.limitations, ...art.errors].map((l, k) => <li key={k}>• {l}</li>)}</ul>
            </Card>
          )}
          <Card title={`Evidence on this artifact (${mine.length})`} pad={false}>
            <Table head={["ID", "Severity", "Source", "Observation"]} rows={mine.slice(0, 60).map((e) => [<Mono>{e.id}</Mono>, <SeverityBadge severity={e.severity} />, e.source_label, e.title])} />
          </Card>
        </div>
      )}
      {tab === "structure" && (!hasStructure ? <Empty>No format-specific structure for this file type.</Empty> :
        m.pe ? <PEView pe={m.pe} suspicious={suspicious} /> : m.elf ? <ELFView elf={m.elf} /> : m.apk ? <APKView apk={m.apk} /> : <DocumentView meta={m} />)}
      {tab === "strings" && <StringsExplorer aid={aid} artifactId={art.id} />}
      {tab === "hex" && <HexView analysisId={aid} artifactId={art.id} />}
      {tab === "raw" && <Card><JsonTree value={m} /></Card>}
    </div>
  );
}

export default function StaticPage() {
  const { a, completed } = useAnalysis();
  const [params, setParams] = useSearchParams();
  const selected = params.get("artifact") || a.artifacts[0]?.id;
  const art = useAsync(() => (selected ? api.artifact(a.id, selected) : Promise.resolve(null)), [a.id, selected, completed]);
  const ev = useAsync(() => (completed ? api.evidence(a.id) : Promise.resolve([])), [a.id, completed]);
  const sorted = useMemo(() => [...a.artifacts].sort((x, y) => x.depth - y.depth), [a.artifacts]);
  if (!completed) return <NotReady />;
  return (
    <div className="grid gap-4 lg:grid-cols-[280px_1fr]">
      <Card title={`Artifacts (${a.artifacts.length})`} pad={false} className="self-start">
        <ul className="max-h-[75vh] overflow-auto py-1">
          {sorted.map((x) => (
            <li key={x.id}>
              <button type="button" onClick={() => setParams({ artifact: x.id })}
                className={cx("w-full px-3 py-2 text-left hover:bg-panel2", selected === x.id && "bg-accent/10")} style={{ paddingLeft: 12 + x.depth * 14 }}>
                <div className="truncate font-mono text-[12.5px]">{x.name}</div>
                <div className="flex items-center gap-1.5 truncate text-[11px] text-muted">{x.detected_type} · {bytes(x.size)} {x.extension_mismatch && <AlertTriangle className="h-3 w-3 text-sev-high" />}</div>
              </button>
            </li>
          ))}
        </ul>
      </Card>
      <div className="min-w-0">{art.data ? <Detail aid={a.id} art={art.data} evidence={ev.data || []} /> : <Spinner />}</div>
    </div>
  );
}
