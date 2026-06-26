export type SecurityAlertRequest = {
  alert_id: string;
  source: string;
  title: string;
  description: string;
  severity?: string | null;
};

export type AlertAnalysisResponse = {
  alert_summary: string;
  severity: string;
  threat_explanation: string;
  mitre_technique: string;
  mitre_tactic: string;
  investigation_steps: string[];
  recommended_response: string[];
  executive_summary: string;
};

export type MitreMappingResponse = {
  technique_id: string | null;
  technique_name: string | null;
  tactic: string | null;
  description: string | null;
  matched_keywords: string[];
  matched_on: string | null;
};

export type ThreatIndicatorRequest = {
  indicator: string;
};

export type VirusTotalLookupResponse = {
  entity: string;
  entity_type: "ip_address" | "domain" | "file_hash";
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
  reputation: number | null;
  tags: string[];
  permalink: string | null;
  last_analysis_stats: Record<string, number>;
  raw_response: Record<string, unknown>;
};

export type AbuseIPDBLookupResponse = {
  ip_address: string;
  abuse_confidence_score: number;
  total_reports: number;
  last_reported_at: string | null;
  country_code: string | null;
  isp: string | null;
  domain: string | null;
  usage_type: string | null;
  raw_response: Record<string, unknown>;
};

export type IncidentReportRequest = {
  alert: SecurityAlertRequest;
  analysis: AlertAnalysisResponse;
  timeline: string[];
  indicators_of_compromise: string[];
};

export type IncidentReportResponse = {
  report_id: string;
  generated_at: string;
  alert_summary: string;
  severity: string;
  threat_explanation: string;
  mitre_technique: string;
  mitre_tactic: string;
  timeline: string[];
  indicators_of_compromise: string[];
  root_cause: string;
  recommended_actions: string[];
  executive_summary: string;
  report_markdown: string;
};

export type SampleLogListResponse = {
  sample_logs: string[];
};

export type SampleLogContentResponse = {
  file_name: string;
  content: string;
};

export type LogAnalysisRequest = {
  log_type: "windows_security" | "linux_syslog" | "apache" | "authentication";
  content: string;
};

export type LogAnalysisResponse = AlertAnalysisResponse;

export type WazuhAnalysisItem = {
  source_alert: Record<string, unknown>;
  parsed_alert: SecurityAlertRequest;
  mitre_mapping: MitreMappingResponse;
  analysis: AlertAnalysisResponse;
  report: IncidentReportResponse;
};

export type WazuhBatchResponse = {
  source_file: string;
  alert_count: number;
  results: WazuhAnalysisItem[];
};

export type ElasticsearchSearchHit = {
  index: string;
  document_id: string;
  score: number | null;
  source: Record<string, unknown>;
};

export type ElasticsearchSearchResponse = {
  query: string;
  index: string;
  total: number;
  hits: ElasticsearchSearchHit[];
  raw_response: Record<string, unknown>;
};

export type ExtractedIOC = {
  indicator: string;
  indicator_type: 'ip' | 'domain' | 'url' | 'file_hash' | 'username';
  virustotal?: {
    malicious: number;
    suspicious: number;
    reputation: number | null;
    permalink: string | null;
  } | null;
  abuseipdb?: {
    confidence_score: number;
    total_reports: number;
    country_code: string | null;
    isp: string | null;
  } | null;
};

export type InvestigationResponse = {
  summary: string;
  iocs: ExtractedIOC[];
  recommended_investigation_steps: string[];
  containment_actions: string[];
  recovery_actions: string[];
  detection_recommendations: string[];
  confidence_score: number;
};
