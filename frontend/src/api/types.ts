export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Classification = "UNKNOWN" | "BENIGN_INDICATORS" | "SUSPICIOUS" | "HIGHLY_SUSPICIOUS" | "MALICIOUS_INDICATORS";
export type AnalystState = "UNKNOWN" | "INVESTIGATING" | "SUPPORTED" | "CONFIRMED" | "DISMISSED";
export type Status = "QUEUED" | "VALIDATING" | "EXTRACTING" | "ANALYZING" | "CORRELATING" | "REPORTING" | "COMPLETED" | "FAILED" | "CANCELLED";

export interface AnalysisSummary {
  id: string;
  name: string;
  mode: string;
  status: Status;
  progress: number;
  stage_detail: string | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  classification: Classification | null;
  risk_score: number | null;
  main_type: string | null;
  sha256: string | null;
  artifact_count: number;
  finding_count: number;
  evidence_count: number;
  ioc_count: number;
  notes: string | null;
}

export interface RiskDimension { label: string; score: number; reasons: { ref: string; title: string; contribution: number }[] }
export interface ChainStage { stage: string; label: string; count: number; refs: string[] }
export interface Capability { category: string; label: string; count: number; max_severity: Severity; evidence: string[] }

export interface InvestigationSummary {
  narrative: string[];
  observations: number;
  interesting: number;
  suspicious: number;
  correlated: number;
  findings: number;
  strong: number;
  needs_review: number;
  weak: number;
  main_hypothesis: { ref: string; title: string; hypothesis: string | null } | null;
  chain: ChainStage[];
  classification: Classification;
  classification_reason: string;
  severity_counts: Record<Severity, number>;
  capabilities: Capability[];
}

export interface ArtifactBrief {
  id: string;
  parent_id: string | null;
  depth: number;
  name: string;
  path_in_archive: string | null;
  size: number;
  sha256: string | null;
  detected_type: string | null;
  type_label: string | null;
  category: string | null;
  extension_mismatch: boolean;
  entropy: number | null;
  architecture: string | null;
  tags: string[];
  has_reverse: boolean;
  string_count: number;
}

export interface AnalysisDetail extends AnalysisSummary {
  risk: { overall: number; dimensions: Record<string, RiskDimension>; note: string } | null;
  summary: InvestigationSummary | null;
  engines: Record<string, any> | null;
  limitations: string[];
  files: { name: string; size: number }[];
  has_appsec: boolean;
  artifacts: ArtifactBrief[];
  severity_counts: Record<Severity, number>;
}

export interface ArtifactDetail extends ArtifactBrief {
  hashes: Record<string, string | null>;
  identification: {
    detected_type: string; label: string; category: string; mime: string; confidence: number; parser: string;
    extension: string; magic_hex: string; size: number; sha256: string; extension_mismatch: boolean;
    mismatch_reason: string | null; details: Record<string, any>;
  };
  entropy_profile: number[];
  name_issues: string[];
  limitations: string[];
  errors: string[];
  metadata: Record<string, any>;
}

export interface Evidence {
  id: string;
  uid: string;
  type: string;
  category: string;
  source: string;
  source_label: string;
  artifact_id: string | null;
  artifact: string | null;
  value: string | null;
  severity: Severity;
  confidence: number;
  reliability: string;
  title: string;
  description: string;
  details: Record<string, any>;
  rule_id: string | null;
  mitre: string[];
  offset: number | null;
  observed_at: string | null;
  analyst_state: AnalystState;
  analyst_note: string | null;
  related_findings: string[];
}

export interface FindingEvidence {
  id: string; role: string; title: string; severity: Severity; source: string; source_label: string;
  confidence: number; value: string | null; type: string; category: string;
}

export interface Finding {
  id: string;
  uid: string;
  title: string;
  kind: "correlated" | "indicator" | "appsec" | "analyst";
  category: string;
  severity: Severity;
  confidence: number;
  strength: "strong" | "moderate" | "weak";
  needs_review: boolean;
  what: string;
  where: string[];
  why: string;
  limitations: string[];
  recommendation: string | null;
  hypothesis: string | null;
  rule_id: string | null;
  mitre: string[];
  cwe: string | null;
  score: number;
  status: AnalystState;
  analyst_note: string | null;
  evidence: FindingEvidence[];
  sources: string[];
}

export interface IOC {
  type: string; value: string; normalized: string; common: boolean; source: string; artifact_id: string | null;
  offset: number | null; occurrences: number; evidence_ref: string | null; context: string | null;
  analysis_id: string; analysis_name: string;
}

export interface MitreTechnique {
  technique_id: string; name: string; tactics: string[]; evidence: string[]; findings: string[]; reason: string;
  confidence: number; sources: string[]; url: string;
}

export interface GraphNode {
  id: string; type: "sample" | "artifact" | "engine" | "evidence" | "finding" | "mitre" | "classification";
  layer: number; label: string; sublabel?: string; ref: string; severity: Severity | null; category?: string;
}
export interface GraphEdge { source: string; target: string; relationship: string; evidence_id: string | null; confidence: number }
export interface GraphData { nodes: GraphNode[]; edges: GraphEdge[] }

export interface TimelineEvent {
  ts: string; lane: string; event: string; engine: string | null; artifact_id: string | null; evidence_ref: string | null; detail: string | null;
}

export interface ReverseFunction {
  address: string; name: string; source: string; size: number; instructions: number; truncated: boolean;
  callers: string[]; callees: string[]; xrefs: string[]; imports: string[]; strings: { address: string; value: string }[];
  segment: string | null; has_pseudocode?: boolean;
  assembly?: { address: string; bytes: string; mnemonic: string; operands: string; import?: string; string?: string; call?: string }[];
  pseudocode?: string; pseudocode_note?: string | null;
  segment_info?: { name: string; start: string; size: number; executable: boolean; entropy: number } | null;
  related?: { evidence: string; title: string; severity: Severity; findings: string[] }[];
}

export interface Board {
  nodes: any[];
  edges: any[];
  notes: string | null;
}

export interface SystemInfo {
  version: string;
  privacy: string;
  offline: boolean;
  execution_policy: string;
  external_integrations: string;
  limits: Record<string, number>;
  workers: Record<string, any>;
  rules: Record<string, any>;
  advisories: { directory: string; packages: number; advisories: number };
  storage: { root: string; usage_bytes: Record<string, number> };
  database: string;
  engines: Record<string, any>;
  tools: { name: string; path: string | null; version: string | null; purpose: string; available: boolean; enabled: boolean }[];
  python: string;
  platform: string;
}
