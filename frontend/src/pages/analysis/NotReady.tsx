import { Loader2 } from "lucide-react";
import { Empty } from "../../components/ui";
import { useAnalysis } from "./context";

/** Placeholder shown by result tabs while the analysis is still running (or failed). */
export default function NotReady() {
  const { a } = useAnalysis();
  if (a.status === "FAILED" || a.status === "CANCELLED")
    return <Empty>This analysis {a.status.toLowerCase()}{a.error ? `: ${a.error}` : ""}. Partial results are not available.</Empty>;
  return (
    <Empty icon={<Loader2 className="h-6 w-6 animate-spin text-accent" />}>
      The isolated worker is still analysing the sample ({a.status.toLowerCase()}, {a.progress}%). Results appear here when correlation completes.
    </Empty>
  );
}
