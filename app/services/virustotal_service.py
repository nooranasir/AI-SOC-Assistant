"""VirusTotal integration service.

Purpose:
    Query VirusTotal for IPs, domains, URLs, and file hashes, then convert the
    response into a normalized structure that can enrich AI analysis.

Inputs:
    Indicators extracted from alerts or provided directly by API clients.

Outputs:
    Normalized VirusTotal lookup results.

Dependencies:
    requests for HTTPS API calls and the shared AI analysis service.
"""

import base64
from dataclasses import dataclass
import datetime
import ipaddress
from typing import Any

import requests

from app.core.config import Settings
from app.schemas.alert import AlertAnalysisResponse, SecurityAlertRequest
from app.schemas.integrations import IndicatorType, ThreatIndicatorRequest, VirusTotalLookupResponse
from app.services.ai_service import AIAlertAnalysisService
from app.services.indicator_extractor import IndicatorExtractor


@dataclass(slots=True)
class VirusTotalService:
    """Query VirusTotal and integrate the result into AI analysis."""

    settings: Settings
    ai_service: AIAlertAnalysisService
    extractor: IndicatorExtractor

    @classmethod
    def from_settings(cls, settings: Settings, ai_service: AIAlertAnalysisService) -> "VirusTotalService":
        """Build the service from application settings."""
        return cls(settings=settings, ai_service=ai_service, extractor=IndicatorExtractor())

    def lookup(self, request: ThreatIndicatorRequest) -> VirusTotalLookupResponse:
        """Query VirusTotal for a single indicator."""
        entity_type = self._detect_entity_type(request.indicator)

        if not self.settings.virustotal_api_key:
            return VirusTotalLookupResponse(
                entity=request.indicator,
                entity_type=entity_type,
                status="not_configured",
                message="VirusTotal API key not configured.",
                malicious=0,
                suspicious=0,
                harmless=0,
                undetected=0,
                timeout=0,
                raw_response={},
            )

        endpoint = self._build_endpoint(entity_type, request.indicator)
        response = requests.get(
            endpoint,
            headers={"x-apikey": self.settings.virustotal_api_key},
            timeout=20,
        )
        response.raise_for_status()
        raw_response = response.json()
        attributes = raw_response.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        votes = attributes.get("total_votes", {})

        # Format last analysis date/time
        last_analysis_time = attributes.get("last_analysis_date")
        last_analysis_str = None
        if last_analysis_time:
            try:
                last_analysis_str = datetime.datetime.fromtimestamp(
                    int(last_analysis_time),
                    tz=datetime.timezone.utc
                ).strftime('%Y-%m-%d %H:%M:%S UTC')
            except Exception:
                pass

        # Extract permalink or construct it dynamically
        permalink = attributes.get("permalink")
        if not permalink:
            base_gui_url = "https://www.virustotal.com/gui"
            indicator_stripped = request.indicator.strip()
            if entity_type is IndicatorType.ip_address:
                permalink = f"{base_gui_url}/ip-address/{indicator_stripped}"
            elif entity_type is IndicatorType.domain:
                permalink = f"{base_gui_url}/domain/{indicator_stripped}"
            elif entity_type is IndicatorType.file_hash:
                permalink = f"{base_gui_url}/file/{indicator_stripped}"
            elif entity_type is IndicatorType.url:
                url_id = base64.urlsafe_b64encode(indicator_stripped.encode("utf-8")).decode("utf-8").rstrip("=")
                permalink = f"{base_gui_url}/url/{url_id}"

        return VirusTotalLookupResponse(
            entity=request.indicator,
            entity_type=entity_type,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            timeout=int(stats.get("timeout", 0)),
            reputation=attributes.get("reputation"),
            tags=list(attributes.get("tags", [])),
            permalink=permalink,
            last_analysis_stats={
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0)),
                "timeout": int(stats.get("timeout", 0)),
            },
            raw_response=raw_response,
            status="success",
            community_votes={
                "harmless": int(votes.get("harmless", 0)),
                "malicious": int(votes.get("malicious", 0)),
            },
            last_analysis=last_analysis_str,
        )

    def analyze_alert(self, alert: SecurityAlertRequest) -> AlertAnalysisResponse:
        """Enrich an alert with VirusTotal lookups and send it through AI analysis."""
        indicators = self._extract_indicators(alert)
        enrichment_lines: list[str] = []
        for indicator in indicators:
            try:
                lookup_result = self.lookup(ThreatIndicatorRequest(indicator=indicator))
                if lookup_result.status != "success":
                    continue
            except Exception as exc:
                enrichment_lines.append(f"VirusTotal lookup failed for {indicator}: {exc}")
                continue
            enrichment_lines.append(
                f"VirusTotal {lookup_result.entity_type.value} {lookup_result.entity}: "
                f"malicious={lookup_result.malicious}, suspicious={lookup_result.suspicious}, "
                f"reputation={lookup_result.reputation}"
            )
        enrichment_context = "\n".join(enrichment_lines) if enrichment_lines else None
        return self.ai_service.analyze(alert, enrichment_context=enrichment_context)

    def _extract_indicators(self, alert: SecurityAlertRequest) -> list[str]:
        """Extract IPs, domains, URLs, and hashes from an alert."""
        content = f"{alert.title}\n{alert.description}"
        indicators = []
        indicators.extend(self.extractor.extract_ips(content))
        indicators.extend(self.extractor.extract_domains(content))
        indicators.extend(self.extractor.extract_urls(content))
        indicators.extend(self.extractor.extract_hashes(content))
        return indicators

    def _detect_entity_type(self, indicator: str) -> IndicatorType:
        """Detect whether the indicator is an IP, domain, URL, or hash."""
        indicator_stripped = indicator.strip()
        if indicator_stripped.lower().startswith(("http://", "https://")):
            return IndicatorType.url
        try:
            ipaddress.ip_address(indicator_stripped)
            return IndicatorType.ip_address
        except ValueError:
            pass
        if self._looks_like_hash(indicator_stripped):
            return IndicatorType.file_hash
        return IndicatorType.domain

    def _build_endpoint(self, entity_type: IndicatorType, indicator: str) -> str:
        """Build the VirusTotal API endpoint for the requested entity."""
        base_url = self.settings.virustotal_base_url.rstrip("/")
        if entity_type is IndicatorType.url:
            url_id = base64.urlsafe_b64encode(indicator.strip().encode("utf-8")).decode("utf-8").rstrip("=")
            return f"{base_url}/urls/{url_id}"
        
        encoded_indicator = requests.utils.quote(indicator.strip(), safe="")
        if entity_type is IndicatorType.ip_address:
            return f"{base_url}/ip_addresses/{encoded_indicator}"
        if entity_type is IndicatorType.file_hash:
            return f"{base_url}/files/{encoded_indicator}"
        return f"{base_url}/domains/{encoded_indicator}"

    def _looks_like_hash(self, indicator: str) -> bool:
        """Return True when the value looks like a supported hash format."""
        normalized = indicator.strip()
        return len(normalized) in {32, 40, 64} and all(character in "0123456789abcdefABCDEF" for character in normalized)
