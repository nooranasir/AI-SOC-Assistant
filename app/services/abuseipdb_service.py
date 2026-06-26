"""AbuseIPDB integration service.

Purpose:
    Query AbuseIPDB for IP reputation data and enrich AI analysis with the
    normalized result. Disabled for version 1 of this project.

Inputs:
    Source IP addresses extracted from alerts or provided directly.

Outputs:
    Normalized AbuseIPDB enrichment data.

Dependencies:
    requests for HTTPS API calls and the shared AI analysis service.
"""

from dataclasses import dataclass
from typing import Any

from app.core.config import Settings
from app.schemas.alert import AlertAnalysisResponse, SecurityAlertRequest
from app.schemas.integrations import AbuseIPDBLookupResponse, ThreatIndicatorRequest
from app.services.ai_service import AIAlertAnalysisService
from app.services.indicator_extractor import IndicatorExtractor


@dataclass(slots=True)
class AbuseIPDBService:
    """Query AbuseIPDB and integrate the result into AI analysis."""

    settings: Settings
    ai_service: AIAlertAnalysisService
    extractor: IndicatorExtractor

    @classmethod
    def from_settings(cls, settings: Settings, ai_service: AIAlertAnalysisService) -> "AbuseIPDBService":
        """Build the service from application settings."""
        return cls(settings=settings, ai_service=ai_service, extractor=IndicatorExtractor())

    def check_ip(self, request: ThreatIndicatorRequest) -> AbuseIPDBLookupResponse:
        """Query AbuseIPDB for a single IP address (disabled for version 1)."""
        return AbuseIPDBLookupResponse(
            status="offline",
            message="AbuseIPDB integration is disabled in this version.",
            ip_address=request.indicator,
            abuse_confidence_score=0,
            total_reports=0,
            raw_response={},
        )

    def analyze_alert(self, alert: SecurityAlertRequest) -> AlertAnalysisResponse:
        """Enrich an alert with AbuseIPDB data and send it through AI analysis."""
        indicators = self.extractor.extract_ips(f"{alert.title}\n{alert.description}")
        enrichment_lines: list[str] = []
        for indicator in indicators:
            try:
                lookup_result = self.check_ip(ThreatIndicatorRequest(indicator=indicator))
                if lookup_result.status != "online":
                    continue
            except Exception as exc:
                enrichment_lines.append(f"AbuseIPDB lookup failed for {indicator}: {exc}")
                continue
            enrichment_lines.append(
                f"AbuseIPDB {lookup_result.ip_address}: score={lookup_result.abuse_confidence_score}, "
                f"reports={lookup_result.total_reports}, country={lookup_result.country_code}"
            )
        enrichment_context = "\n".join(enrichment_lines) if enrichment_lines else None
        return self.ai_service.analyze(alert, enrichment_context=enrichment_context)
