export type Verdict =
  | 'INCIDENT'
  | 'ACT_NOW'
  | 'UPGRADE'
  | 'MONITOR'
  | 'REVIEW'
  | 'CANNOT_ASSESS'
  | 'NO_KNOWN_FINDING';

export type Urgency =
  | 'IMMEDIATE'
  | 'OUT_OF_CYCLE'
  | 'SCHEDULED'
  | 'DEFER'
  | 'NONE';

export type Qualifier =
  | 'ESTABLISHED'
  | 'PROBABLE'
  | 'POSSIBLE'
  | 'UNKNOWN';

export type ResponseClass =
  | 'containment'
  | 'minimal_upgrade'
  | 'upgrade'
  | 'defer'
  | 'review'
  | 'cannot_assess'
  | 'none';

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
  INCIDENT: '⛔',
  ACT_NOW: '▲',
  UPGRADE: '↑',
  MONITOR: '◔',
  REVIEW: '◇',
  CANNOT_ASSESS: '⊘',
  NO_KNOWN_FINDING: '○',
};

export interface ExposureInfo {
  paths: string[][];
  scope: string;
  scope_provenance: string;
  install_phase: string;
  scripts_enabled: string;
}

export interface RemediationStep {
  text: string;
  command?: string | null;
}

export interface Decision {
  subject: string;
  name: string;
  version: string;
  verdict: Verdict;
  urgency: Urgency;
  qualifier: Qualifier;
  exposure: ExposureInfo;
  evidence_ids: string[];
  open_defeaters: string[];
  unrun_checks: string[];
  response: ResponseClass;
  response_steps: RemediationStep[];
  as_of: string;
  derivation: string[];
  introduced_by: string[];
  fixed_version?: string | null;
  depth: number;
  is_direct: boolean;
  cvss_vector?: string | null;
  cvss_severity?: string | null;
  what: string;
  carry_reason?: string | null;
}

export interface EvidenceRecord {
  id: string;
  tier: string;
  source: string;
  origin: string;
  kind: string;
  subject: string;
  claim: string;
  url?: string | null;
  published_at?: string | null;
  retrieved_at: string;
  quote?: string | null;
  withdrawn: boolean;
  data?: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  name: string;
  version: string;
  is_direct: boolean;
  scope: string;
  depth: number;
  has_install_script: boolean;
  resolved_url?: string | null;
  is_git_or_file: boolean;
  verdict?: string | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  requirement?: string | null;
  scope: string;
}

export interface LicenseResult {
  subject: string;
  name: string;
  version: string;
  license_expr?: string | null;
  license_status: string;
  rule_fired?: string | null;
  introducing_paths: string[][];
  note?: string | null;
}

export interface CoverageCheck {
  check: string;
  status: string;
  reason?: string | null;
  count?: number | null;
}

export interface ReportSummary {
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
  data_badge: string;
}

export interface CompanyPolicy {
  id: string;
  company_name: string;
  short_name: string;
  official_policy_name: string;
  source_url: string;
  summary: string;
  allowed_licenses: string[];
  banned_licenses: string[];
  restricted_licenses: string[];
  restricted_condition: string;
  banned_rationale: string;
}

export interface AnalysisContext {
  distribution_mode: string;
  project_license: string;
  install_scripts_run?: boolean | null;
  company_policy?: string | null;
  banned_dependencies?: string[];
  skipped_fields: string[];
}

export interface Report {
  id: string;
  created_at: string;
  meta: Record<string, unknown>;
  summary: ReportSummary;
  decisions: Decision[];
  evidence: EvidenceRecord[];
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  licenses: LicenseResult[];
  coverage: CoverageCheck[];
  context: AnalysisContext;
  schema_version: string;
}
