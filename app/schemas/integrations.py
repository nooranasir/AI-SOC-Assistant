"""Integration response schemas for external security services.

Purpose:
    Define typed request and response models for Wazuh, VirusTotal,
    AbuseIPDB, and Elasticsearch integrations.

Inputs:
    Exported alerts, indicators, and search queries.

Outputs:
    Normalized integration payloads.

Dependencies:
    pydantic for validation and schema generation.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.alert import AlertAnalysisResponse, SecurityAlertRequest
from app.schemas.mitre import MitreMappingResponse
from app.schemas.report import IncidentReportResponse


class IndicatorType(str, Enum):
    """Supported indicator types for threat-intelligence lookups."""

    ip_address = "ip_address"
    domain = "domain"
    file_hash = "file_hash"
    url = "url"


class WazuhAnalysisItem(BaseModel):
    """Normalized Wazuh alert analysis result."""

    source_alert: dict[str, Any] = Field(..., description="Raw Wazuh alert event")
    parsed_alert: SecurityAlertRequest = Field(..., description="Parsed alert schema")
    mitre_mapping: MitreMappingResponse = Field(..., description="Local MITRE mapping result")
    analysis: AlertAnalysisResponse = Field(..., description="AI analysis result")
    report: IncidentReportResponse = Field(..., description="Generated incident report")


class WazuhBatchResponse(BaseModel):
    """Batch response for exported Wazuh alerts."""

    source_file: str = Field(..., description="Source alerts file")
    alert_count: int = Field(..., description="Number of parsed alerts")
    results: list[WazuhAnalysisItem] = Field(..., description="Per-alert analysis results")


class ThreatIndicatorRequest(BaseModel):
    """Request body for indicator lookups."""

    indicator: str = Field(..., min_length=1, description="IP, domain, or hash to query")


class SearchRequest(BaseModel):
    """Request body for Elasticsearch searches."""

    query: str = Field(..., min_length=1, description="Search query")
    size: int = Field(default=10, ge=1, le=100, description="Maximum number of hits")


class VirusTotalLookupResponse(BaseModel):
    """Normalized VirusTotal lookup result."""

    entity: str = Field(default="", description="Queried indicator")
    entity_type: IndicatorType = Field(default=IndicatorType.ip_address, description="Detected entity type")
    malicious: int = Field(default=0, description="Malicious detections")
    suspicious: int = Field(default=0, description="Suspicious detections")
    harmless: int = Field(default=0, description="Harmless detections")
    undetected: int = Field(default=0, description="Undetected results")
    timeout: int = Field(default=0, description="Timeout results")
    reputation: int | None = Field(default=None, description="Entity reputation score")
    tags: list[str] = Field(default_factory=list, description="Entity tags")
    permalink: str | None = Field(default=None, description="VirusTotal link")
    last_analysis_stats: dict[str, int] = Field(
        default_factory=dict,
        description="Normalized VirusTotal analysis statistics",
    )
    raw_response: dict[str, Any] = Field(default_factory=dict, description="Original API response")
    status: str = Field(default="success", description="Response status (success or not_configured)")
    message: str | None = Field(default=None, description="Optional status message")
    community_votes: dict[str, int] = Field(default_factory=dict, description="Community votes statistics")
    last_analysis: str | None = Field(default=None, description="Human-readable last analysis date/time")


class AbuseIPDBLookupResponse(BaseModel):
    """Normalized AbuseIPDB lookup result."""

    ip_address: str = Field(default="", description="Queried IP address")
    abuse_confidence_score: int = Field(default=0, description="Confidence score")
    total_reports: int = Field(default=0, description="Total number of abuse reports")
    last_reported_at: str | None = Field(default=None, description="Last report timestamp")
    country_code: str | None = Field(default=None, description="Country code")
    isp: str | None = Field(default=None, description="Internet service provider")
    domain: str | None = Field(default=None, description="Observed domain")
    usage_type: str | None = Field(default=None, description="Address usage type")
    raw_response: dict[str, Any] = Field(default_factory=dict, description="Original API response")
    status: str = Field(default="online", description="Integration status (online or offline)")
    message: str | None = Field(default=None, description="Optional status message")


class ElasticsearchSearchHit(BaseModel):
    """Normalized Elasticsearch search hit."""

    index: str = Field(..., description="Elasticsearch index")
    document_id: str = Field(..., description="Document identifier")
    score: float | None = Field(default=None, description="Match score")
    source: dict[str, Any] = Field(..., description="Document source")


class ElasticsearchSearchResponse(BaseModel):
    """Normalized Elasticsearch search response."""

    query: str = Field(..., description="Search query")
    index: str = Field(..., description="Target index")
    total: int = Field(default=0, description="Total hits")
    hits: list[ElasticsearchSearchHit] = Field(
        default_factory=list,
        description="Normalized hits",
    )
    raw_response: dict[str, Any] = Field(
        default_factory=dict,
        description="Original Elasticsearch response",
    )
    status: str = Field(default="online", description="Elasticsearch status (online or offline)")
    message: str | None = Field(default=None, description="Optional status or error message")

