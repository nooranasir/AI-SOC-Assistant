import type {
  AbuseIPDBLookupResponse,
  AlertAnalysisResponse,
  ElasticsearchSearchResponse,
  IncidentReportRequest,
  IncidentReportResponse,
  LogAnalysisRequest,
  LogAnalysisResponse,
  MitreMappingResponse,
  SampleLogContentResponse,
  SampleLogListResponse,
  SecurityAlertRequest,
  ThreatIndicatorRequest,
  VirusTotalLookupResponse,
  WazuhBatchResponse,
  InvestigationResponse,
} from "../types/api";

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new ApiError(errorText || `Request failed with status ${response.status}`, response.status);
  }

  return (await response.json()) as T;
}

export async function getHealth(): Promise<{ status: string; service: string }> {
  return request<{ status: string; service: string }>("/health");
}

export const api = {
  analyzeAlert(alert: SecurityAlertRequest): Promise<AlertAnalysisResponse> {
    return request<AlertAnalysisResponse>("/alerts/analyze", {
      method: "POST",
      body: JSON.stringify(alert),
    });
  },
  investigateAlert(alert: SecurityAlertRequest): Promise<InvestigationResponse> {
    return request<InvestigationResponse>("/alerts/investigate", {
      method: "POST",
      body: JSON.stringify(alert),
    });
  },
  parseAlert(payload: Record<string, unknown>): Promise<SecurityAlertRequest> {
    return request<SecurityAlertRequest>("/alerts/parse", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },
  analyzeLog(requestBody: LogAnalysisRequest): Promise<LogAnalysisResponse> {
    return request<LogAnalysisResponse>("/logs/analyze", {
      method: "POST",
      body: JSON.stringify(requestBody),
    });
  },
  listSampleLogs(): Promise<SampleLogListResponse> {
    return request<SampleLogListResponse>("/logs/samples");
  },
  loadSampleLog(sampleName: string): Promise<SampleLogContentResponse> {
    return request<SampleLogContentResponse>(`/logs/samples/${encodeURIComponent(sampleName)}`);
  },
  mapMitre(text: string): Promise<MitreMappingResponse> {
    return request<MitreMappingResponse>("/mitre/map", {
      method: "POST",
      body: JSON.stringify({ text }),
    });
  },
  lookupVirusTotal(indicator: ThreatIndicatorRequest): Promise<VirusTotalLookupResponse> {
    return request<VirusTotalLookupResponse>("/virustotal/lookup", {
      method: "POST",
      body: JSON.stringify(indicator),
    });
  },
  lookupAbuseIpdb(indicator: ThreatIndicatorRequest): Promise<AbuseIPDBLookupResponse> {
    return request<AbuseIPDBLookupResponse>("/abuseipdb/check", {
      method: "POST",
      body: JSON.stringify(indicator),
    });
  },
  generateIncidentReport(requestBody: IncidentReportRequest): Promise<IncidentReportResponse> {
    return request<IncidentReportResponse>("/reports/incidents", {
      method: "POST",
      body: JSON.stringify(requestBody),
    });
  },
  analyzeWazuhAlert(payload: unknown): Promise<WazuhBatchResponse> {
    return request<WazuhBatchResponse>("/wazuh/alert", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },
  loadWazuhSample(): Promise<WazuhBatchResponse> {
    return request<WazuhBatchResponse>("/wazuh/sample");
  },
  searchElasticsearchAlerts(query: string, size = 10): Promise<ElasticsearchSearchResponse> {
    return request<ElasticsearchSearchResponse>("/elasticsearch/alerts/search", {
      method: "POST",
      body: JSON.stringify({ query, size }),
    });
  },
  searchElasticsearchLogs(query: string, size = 10): Promise<ElasticsearchSearchResponse> {
    return request<ElasticsearchSearchResponse>("/elasticsearch/logs/search", {
      method: "POST",
      body: JSON.stringify({ query, size }),
    });
  },
  ApiError,
};

export type { ApiError };
