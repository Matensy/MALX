import { Download, FileJson, FileText, Globe2, ListTree, Printer } from "lucide-react";
import { urls } from "../../api/client";
import { Button, Card } from "../../components/ui";
import { download } from "../../lib/format";
import { useAnalysis } from "./context";
import NotReady from "./NotReady";

export default function ReportPage() {
  const { a, completed } = useAnalysis();
  if (!completed) return <NotReady />;
  const exports = [
    { label: "Export report (HTML)", icon: Globe2, url: urls.report(a.id, "html", true) },
    { label: "Export Markdown", icon: FileText, url: urls.report(a.id, "md", true) },
    { label: "Export report (JSON)", icon: FileJson, url: urls.report(a.id, "json", true) },
    { label: "Export evidence", icon: ListTree, url: urls.export(a.id, "evidence") },
    { label: "Export analysis JSON", icon: FileJson, url: urls.export(a.id, "analysis") },
    { label: "Export IOCs (CSV)", icon: Download, url: urls.iocs(a.id, "csv") },
  ];
  return (
    <div className="space-y-4">
      <Card title="Exports">
        <div className="flex flex-wrap gap-2">
          {exports.map((e) => <Button key={e.label} onClick={() => download(e.url)}><e.icon className="h-4 w-4" /> {e.label}</Button>)}
          <Button onClick={() => window.open(urls.report(a.id, "html"), "_blank", "noopener")}><Printer className="h-4 w-4" /> Open printable view (PDF via print)</Button>
        </div>
        <p className="mt-3 text-[12px] text-muted">Reports contain masked secrets only and never the archive password. Values from samples are escaped; the HTML report runs no scripts (strict CSP). Native PDF export is on the roadmap.</p>
      </Card>
      <div className="overflow-hidden rounded-xl border border-line bg-white/5">
        {/* sandbox="" blocks scripts, forms and navigation inside the preview */}
        <iframe title="MALX report" src={urls.report(a.id, "html")} sandbox="" className="h-[78vh] w-full bg-bg" referrerPolicy="no-referrer" />
      </div>
    </div>
  );
}
