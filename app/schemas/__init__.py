"""FastAPI request and response schemas for AI SOC Assistant."""

from app.schemas.alert import (
    AlertAnalysisResponse,
    SecurityAlertRequest,
)
from app.schemas.integrations import (
    AbuseIPDBLookupResponse,
    ElasticsearchSearchHit,
    ElasticsearchSearchResponse,
    IndicatorType,
    SearchRequest,
    ThreatIndicatorRequest,
    VirusTotalLookupResponse,
    WazuhAnalysisItem,
    WazuhBatchResponse,
)
from app.schemas.logs import (
    LogAnalysisRequest,
    SampleLogContentResponse,
    SampleLogListResponse,
    SupportedLogType,
)
from app.schemas.mitre import (
    MitreMappingRequest,
    MitreMappingResponse,
    MitreTechniqueRecord,
)
from app.schemas.report import (
    IncidentReportRequest,
    IncidentReportResponse,
)

__all__ = [
    "AlertAnalysisResponse",
    "AbuseIPDBLookupResponse",
    "ElasticsearchSearchHit",
    "ElasticsearchSearchResponse",
    "IndicatorType",
    "SearchRequest",
    "ThreatIndicatorRequest",
    "VirusTotalLookupResponse",
    "WazuhAnalysisItem",
    "WazuhBatchResponse",
    "MitreMappingRequest",
    "MitreMappingResponse",
    "MitreTechniqueRecord",
    "IncidentReportRequest",
    "IncidentReportResponse",
    "LogAnalysisRequest",
    "SampleLogContentResponse",
    "SampleLogListResponse",
    "SecurityAlertRequest",
    "SupportedLogType",
]
