import { createContext, useContext } from "react";
import type { AnalysisDetail } from "../../api/types";

export interface AnalysisCtx {
  a: AnalysisDetail;
  reload: () => void;
  completed: boolean;
}

export const AnalysisContext = createContext<AnalysisCtx | null>(null);

export function useAnalysis(): AnalysisCtx {
  const v = useContext(AnalysisContext);
  if (!v) throw new Error("AnalysisContext missing");
  return v;
}
