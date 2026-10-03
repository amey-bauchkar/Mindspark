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
  INCIDENT: '🔴',
  ACT_NOW: '🟠',
  UPGRADE: '🟡',
  MONITOR: '🔵',
  REVIEW: '🟣',
  CANNOT_ASSESS: '⬜',
  NO_KNOWN_FINDING: '⚪',
};

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

export interface RemediationStep {
  text: string;
  command?: string | null;
}

export interface ExposureInfo {
  paths: string[][];
  scope: string;
  scope_provenance: string;
  install_phase: string;
  scripts_enabled: string;
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

export type EvidenceTier = 'T1' | 'T2' | 'T3' | 'CONTEXT' | 'ABSENT';

export type EvidenceKind =
  | 'malware_report'
  | 'advisory'
  | 'kev'
  | 'epss'
  | 'lookalike'
  | 'stale'
  | 'very_new'
  | 'license'
  | 'install_script'
  | 'scope'
  | 'unresolved_source'
  | 'unresolved_edges'
  | 'injection_suspect'
  | 'other';

export interface EvidenceRecord {
  id: string;
  tier: EvidenceTier;
  source: string;
  origin: string;
  kind: EvidenceKind;
  subject: string;
  claim: string;
  url?: string | null;
  published_at?: string | null;
  retrieved_at: string;
  quote?: string | null;
  withdrawn: boolean;
  data?: Record<string, unknown>;
}

export interface LicenseResult {
  subject: string;
  name: string;
  version: string;
  license_expr?: string | null;
  license_status: string;
  rule_fired?: string | null;
  introducing_paths?: string[][];
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

export interface GraphNode {
  id: string;
  name: string;
  version: string;
  is_direct: boolean;
  scope: string;
  depth: number;
  has_install_script: boolean;
  resolved_url?: string | null;
  is_git_or_file?: boolean;
  verdict?: string | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  requirement?: string | null;
  scope: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AnalysisContext {
  distribution_mode?: string;
  project_license?: string;
  install_scripts_run?: boolean | null;
  skipped_fields?: string[];
}

export interface Report {
  id: string;
  created_at: string;
  meta: Record<string, unknown>;
  summary: ReportSummary;
  decisions: Decision[];
  evidence: EvidenceRecord[];
  graph: GraphData;
  licenses: LicenseResult[];
  coverage: CoverageCheck[];
  context: AnalysisContext;
  schema_version?: string;
}

export interface SampleItem {
  id: string;
  name: string;
  description: string;
  ecosystem: string;
  badge?: string;
}

export interface RecentReport {
  id: string;
  name: string;
  timestamp: string | Date;
  summary: {
    incident: number;
    act_now: number;
    total_packages: number;
  };
}

export interface MethodologyData {
  rules: any[];
  license_rules: any[];
  parameters: Record<string, unknown>;
  current_parameters: {
    epss_threshold: number;
    freshness_hours: number;
  };
  evidence_tiers: {
    tier: string;
    name: string;
    description: string;
  }[];
  verdict_definitions: {
    verdict: string;
    meaning: string;
  }[];
  limitations: string[];
  data_sources: {
    name: string;
    url: string;
    type: string;
  }[];
}
