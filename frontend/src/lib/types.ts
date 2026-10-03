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

export type EvidenceTier = 'T1' | 'T2' | 'T3' | 'CONTEXT' | 'ABSENT' | string;

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
  | 'other'
  | string;

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
  distribution_mode?: string;
  project_license?: string;
  install_scripts_run?: boolean | null;
  company_policy?: string | null;
  banned_dependencies?: string[];
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
  company_policies?: Record<string, CompanyPolicy>;
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

// ─── Warrant Watch (continuous security-evidence monitoring) ────────────────

export type WatchStatus = 'active' | 'paused' | 'disabled';
export type WatchCheckStatus = 'complete' | 'partial' | 'failed' | 'superseded';
export type WatchChangeType = 'ESCALATION' | 'DE_ESCALATION' | 'EVIDENCE_CHANGE';
export type WatchPriority = 'high' | 'medium' | 'low' | 'info';

export interface WatchProviderIssue {
  provider: string;
  detail: string;
  scope: string;
  count: number;
}

export interface WatchCheck {
  id: string;
  watch_id: string;
  trigger: string;
  status: WatchCheckStatus;
  started_at: string;
  finished_at: string;
  evidence_as_of: string;
  summary: string;
  provider_issues: WatchProviderIssue[];
  report_id?: string | null;
  events_created?: number;
  simulated?: boolean;
  label?: string | null;
  held?: string[];
}

export interface WatchDecisionSide {
  verdict: Verdict;
  urgency: Urgency;
  qualifier: Qualifier;
  response: ResponseClass;
  fixed_version?: string | null;
  rules: string[];
  what: string;
  report_id: string;
}

export interface WatchChangedEvidence {
  key: string;
  id: string | null;
  change: string;
  source: string | null;
  origin?: string | null;
  kind?: string | null;
  tier?: string | null;
  subject: string;
  via?: string | null;
  evidence_id?: string | null;
  published_at?: string | null;
  observed_at?: string | null;
  modified_at?: string | null;
  withdrawn: boolean;
  url?: string | null;
  claim?: string | null;
  fixed_version?: string | null;
}

export interface WatchEvent {
  id: string;
  watch_id: string;
  check_id: string;
  title: string;
  project: string;
  subject: string;
  package: string;
  version: string;
  change_type: WatchChangeType;
  priority: WatchPriority;
  previous: WatchDecisionSide;
  current: WatchDecisionSide;
  reason: string;
  reason_lines: string[];
  changed_evidence: WatchChangedEvidence[];
  evidence_sources: string[];
  exposure: { scope: string | null; paths: string[][]; is_direct: boolean; introduced_by: string[] };
  response: { class: ResponseClass; steps: RemediationStep[]; fixed_version?: string | null };
  detected_at: string;
  evidence_as_of: string;
  report_generated_at: string;
  report_id: string;
  previous_report_id: string;
  baseline_report_id: string;
  check_status: WatchCheckStatus;
  mode: 'live' | 'replay';
  simulated: boolean;
  label: string | null;
  acknowledged_at?: string | null;
}

export interface WatchReplay {
  scenario_id: string;
  title: string;
  description: string;
  project: { sample_id: string; authenticity: string; source_url?: string | null; package_count?: number };
  label: string;
  clock: string;
  start: string;
  end: string;
  next_release_at: string | null;
  remaining_steps: number;
  complete: boolean;
  history: { clock: string; advanced_at: string; released: { id: string; change: string; available_at: string }[] }[];
  notes: string[];
}

export interface Watch {
  id: string;
  name: string;
  status: WatchStatus;
  mode: 'live' | 'replay';
  simulated: boolean;
  label: string | null;
  filename: string;
  baseline_report_id: string;
  latest_report_id: string;
  package_count: number;
  direct_count: number;
  analyzed_at: string;
  baseline_as_of: string;
  evidence_as_of: string;
  enabled_at: string;
  last_checked_at: string | null;
  last_check_status: WatchCheckStatus | null;
  last_change_at: string | null;
  next_check_at: string | null;
  interval_seconds: number;
  sources: string[];
  current_verdicts: Record<string, number>;
  event_count: number;
  unacknowledged_count: number;
  last_check: WatchCheck | null;
  latest_event: WatchEvent | null;
  replay: WatchReplay | null;
  events?: WatchEvent[];
  checks?: WatchCheck[];
}

export interface WatchScenario {
  id: string;
  title: string;
  description: string;
  label: string;
  project: { sample_id: string; authenticity: string; source_url?: string | null; package_count?: number };
  start: string;
  end: string;
  steps: string[];
  notes: string[];
}
