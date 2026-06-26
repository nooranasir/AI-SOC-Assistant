"""Integration API routes for external security services."""

from typing import Any
import requests
from fastapi import APIRouter, Body, Depends, HTTPException

from app.core.config import get_settings
from app.schemas.alert import AlertAnalysisResponse, SecurityAlertRequest
from app.schemas.integrations import (
    AbuseIPDBLookupResponse,
    ElasticsearchSearchResponse,
    SearchRequest,
    ThreatIndicatorRequest,
    VirusTotalLookupResponse,
    WazuhBatchResponse,
)
from app.services.abuseipdb_service import AbuseIPDBService
from app.services.ai_service import AIAlertAnalysisService
from app.services.elasticsearch_service import ElasticsearchService
from app.services.virustotal_service import VirusTotalService
from app.services.wazuh_service import WazuhService

router = APIRouter(prefix="", tags=["integrations"])


def get_ai_service() -> AIAlertAnalysisService:
    """Create the shared AI analysis service."""
    return AIAlertAnalysisService.from_settings(get_settings())


def get_wazuh_service() -> WazuhService:
    """Create the Wazuh integration service."""
    settings = get_settings()
    return WazuhService.from_settings(settings, get_ai_service())


def get_virustotal_service() -> VirusTotalService:
    """Create the VirusTotal integration service."""
    settings = get_settings()
    return VirusTotalService.from_settings(settings, get_ai_service())


def get_abuseipdb_service() -> AbuseIPDBService:
    """Create the AbuseIPDB integration service."""
    settings = get_settings()
    return AbuseIPDBService.from_settings(settings, get_ai_service())


def get_elasticsearch_service() -> ElasticsearchService:
    """Create the Elasticsearch integration service."""
    return ElasticsearchService.from_settings(get_settings())


@router.post("/wazuh/alert", response_model=WazuhBatchResponse)
async def analyze_wazuh_alert(
    payload: Any = Body(...),
    service: WazuhService = Depends(get_wazuh_service),
) -> WazuhBatchResponse:
    """Analyze an exported Wazuh alert payload."""
    return service.process_payload(payload, source_file="request-body")


@router.get("/wazuh/sample", response_model=WazuhBatchResponse)
async def analyze_wazuh_sample(
    service: WazuhService = Depends(get_wazuh_service),
) -> WazuhBatchResponse:
    """Analyze the bundled Wazuh export sample."""
    return service.load_sample()


@router.post("/virustotal/lookup", response_model=VirusTotalLookupResponse)
async def lookup_virustotal(
    request: ThreatIndicatorRequest,
    service: VirusTotalService = Depends(get_virustotal_service),
) -> VirusTotalLookupResponse:
    """Look up an IP, domain, or hash in VirusTotal."""
    try:
        return service.lookup(request)
    except requests.Timeout as exc:
        raise HTTPException(status_code=504, detail=f"VirusTotal lookup timed out: {exc}")
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"VirusTotal lookup failed: {exc}")


@router.post("/virustotal/analyze", response_model=AlertAnalysisResponse)
async def analyze_with_virustotal(
    alert: SecurityAlertRequest,
    service: VirusTotalService = Depends(get_virustotal_service),
) -> AlertAnalysisResponse:
    """Analyze an alert with VirusTotal enrichment."""
    return service.analyze_alert(alert)


@router.post("/abuseipdb/check", response_model=AbuseIPDBLookupResponse)
async def check_abuseipdb(
    request: ThreatIndicatorRequest,
    service: AbuseIPDBService = Depends(get_abuseipdb_service),
) -> AbuseIPDBLookupResponse:
    """Check an IP address in AbuseIPDB."""
    return service.check_ip(request)


@router.post("/abuseipdb/analyze", response_model=AlertAnalysisResponse)
async def analyze_with_abuseipdb(
    alert: SecurityAlertRequest,
    service: AbuseIPDBService = Depends(get_abuseipdb_service),
) -> AlertAnalysisResponse:
    """Analyze an alert with AbuseIPDB enrichment."""
    return service.analyze_alert(alert)


@router.post("/elasticsearch/alerts/search", response_model=ElasticsearchSearchResponse)
async def search_elasticsearch_alerts(
    request: SearchRequest,
    service: ElasticsearchService = Depends(get_elasticsearch_service),
) -> ElasticsearchSearchResponse:
    """Search the configured Elasticsearch alerts index."""
    return service.search_alerts(request.query, size=request.size)


@router.post("/elasticsearch/logs/search", response_model=ElasticsearchSearchResponse)
async def search_elasticsearch_logs(
    request: SearchRequest,
    service: ElasticsearchService = Depends(get_elasticsearch_service),
) -> ElasticsearchSearchResponse:
    """Search the configured Elasticsearch logs index."""
    return service.search_logs(request.query, size=request.size)