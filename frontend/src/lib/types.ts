export type Verdict =
  | 'INCIDENT'
  | 'ACT_NOW'
  | 'UPGRADE'
  | 'MONITOR'
  | 'REVIEW'
  | 'CANNOT_ASSESS'
  | 'NO_KNOWN_FINDING';

export const VERDICT_ORDER: Record<Verdict, number> = {
  INCIDENT: 0,
  ACT_NOW: 1,
  UPGRADE: 2,
  MONITOR: 3,
  REVIEW: 4,
  CANNOT_ASSESS: 5,
  NO_KNOWN_FINDING: 6,
};

export const VERDICT_LABELS: Record<Verdict, string> = {
  INCIDENT: 'INCIDENT',
  ACT_NOW: 'ACT NOW',
  UPGRADE: 'UPGRADE',
  MONITOR: 'MONITOR',
  REVIEW: 'REVIEW',
  CANNOT_ASSESS: 'CANNOT ASSESS',
  NO_KNOWN_FINDING: 'NO KNOWN FINDING',
};

export const VERDICT_ICONS: Record<Verdict, string> = {
  INCIDENT: '🚨',
  ACT_NOW: '⚡',
  UPGRADE: '⬆️',
  MONITOR: '👁️',
  REVIEW: '🔍',
  CANNOT_ASSESS: '❓',
  NO_KNOWN_FINDING: '🛡️',
};

export type EvidenceTier = 'T1' | 'T2' | 'T3' | 'CONTEXT' | 'ABSENT';

export interface EvidenceRecord {
  id: string;
  tier: EvidenceTier;
  source: string;
  origin: string;
  kind: string;
  subject: string;
  claim: string;
  url?: string | null;
  published_at?: string | null;
  retrieved_at: string;
  quote?: string | null;
  withdrawn?: boolean;
  data: Record<string, any>;
}

export interface Decision {
  id: string;
  subject: string;
  package_name: string;
  version: string;
  verdict: Verdict;
  rule_id: string;
  rule_description: string;
  headline: string;
  why_it_matters: string;
  how_we_know: string;
  evidence_ids: string[];
  evidence?: EvidenceRecord[];
  remediation?: {
    action: string;
    command?: string;
    pinned_version?: string;
    checklist?: string[];
  } | null;
  unrun_checks?: Array<{
    name: string;
    reason: string;
  }>;
  introduced_by: string[];
  scope: string;
  depth: number;
  has_install_script: boolean;
  is_git_or_file: boolean;
  confidence_level?: string;
  certainty_explanation?: string;
}

export interface LicenseResult {
  purl: string;
  name: string;
  version: string;
  license_expr: string | null;
  license_status: 'OK' | 'REVIEW' | 'CONFLICT' | 'UNKNOWN';
  rule_fired: string;
  note: string;
}

export interface CoverageCheck {
  name: string;
  status: 'passed' | 'skipped' | 'failed';
  target: string;
  reason_if_skipped?: string | null;
  tier: EvidenceTier;
}

export interface GraphNode {
  id: string;
  name: string;
  version: string;
  is_direct: boolean;
  scope: string;
  scope_provenance?: string;
  depth: number;
  has_install_script: boolean;
  is_git_or_file: boolean;
  license?: string | null;
  introduced_by?: string[];
  direct_dependents_count?: number;
  verdict?: Verdict | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  scope: string;
}

export interface AnalysisSummary {
  incident: number;
  act_now: number;
  upgrade: number;
  monitor: number;
  review: number;
  cannot_assess: number;
  no_known_finding: number;
  total_packages: number;
  direct_dependencies: number;
  transitive_dependencies: number;
  licenses_conflict: number;
  licenses_review: number;
}

export interface ReportMeta {
  filename?: string;
  ecosystem?: string;
  created_at: string;
  as_of?: string | null;
}

export interface Report {
  id: string;
  created_at: string;
  meta: ReportMeta;
  summary: AnalysisSummary;
  decisions: Decision[];
  evidence: EvidenceRecord[];
  licenses: LicenseResult[];
  coverage: CoverageCheck[];
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  context?: Record<string, any>;
}
