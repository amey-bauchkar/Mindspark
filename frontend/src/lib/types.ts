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

export interface ExposureInfo {
  paths: string[][];
  scope: string;
  scope_provenance?: string;
  install_phase?: string;
  scripts_enabled?: string;
}

export interface RemediationStep {
  text: string;
  command?: string | null;
}

export interface Decision {
  id?: string;
  subject: string;
  name: string;
  package_name?: string;
  version: string;
  verdict: Verdict;
  urgency?: string;
  qualifier?: string;
  exposure: ExposureInfo;
  evidence_ids: string[];
  evidence?: EvidenceRecord[];
  open_defeaters?: string[];
  unrun_checks?: Array<string | { name: string; reason: string }>;
  response?: string;
  response_steps: RemediationStep[];
  as_of?: string;
  derivation?: string[];
  introduced_by: string[];
  fixed_version?: string | null;
  depth: number;
  is_direct: boolean;
  cvss_vector?: string | null;
  cvss_severity?: string | null;
  what: string;
  carry_reason?: string | null;
  remediation?: {
    action: string;
    command?: string;
    pinned_version?: string;
    checklist?: string[];
  } | null;
  rule_id?: string;
  rule_description?: string;
  headline?: string;
  why_it_matters?: string;
  how_we_know?: string;
  scope?: string;
  has_install_script?: boolean;
  is_git_or_file?: boolean;
  confidence_level?: string;
  certainty_explanation?: string;
}

export interface LicenseResult {
  subject: string;
  name: string;
  version: string;
  license_expr: string | null;
  license_status: 'OK' | 'REVIEW' | 'CONFLICT' | 'UNKNOWN' | 'CANNOT_ASSESS';
  rule_fired?: string | null;
  introducing_paths?: string[][];
  note?: string | null;
}

export interface CoverageCheck {
  check: string;
  status: 'Ran' | 'Partial' | 'Not run' | 'Not supported' | 'passed' | 'skipped' | 'failed';
  reason?: string | null;
  count?: number | null;
  name?: string;
  target?: string;
  reason_if_skipped?: string | null;
  tier?: EvidenceTier;
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
  direct_packages: number;
  as_of: string;
  ecosystem: string;
  data_badge: 'LIVE' | 'RECORDED' | 'REPLAY' | 'PARTIAL' | string;
  direct_dependencies?: number;
  transitive_dependencies?: number;
  licenses_conflict?: number;
  licenses_review?: number;
}

export interface ReportMeta {
  filename?: string;
  ecosystem?: string;
  created_at: string;
  as_of?: string | null;
  [key: string]: any;
}

export interface AnalysisContext {
  distribution_mode?: string;
  project_license?: string;
  install_scripts_run?: boolean | null;
  skipped_fields?: string[];
  [key: string]: any;
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
  context?: AnalysisContext;
}
