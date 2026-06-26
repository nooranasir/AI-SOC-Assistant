"""Schemas for the security alert investigation assistant."""

from typing import Any
from pydantic import BaseModel, Field


class ExtractedIOC(BaseModel):
    """Extracted indicator of compromise with external enrichment."""

    indicator: str = Field(..., description="The indicator value (e.g. IP, domain, hash)")
    indicator_type: str = Field(..., description="Type of indicator: ip, domain, url, file_hash, username")
    virustotal: dict[str, Any] | None = Field(default=None, description="VirusTotal reputation data if queried")
    abuseipdb: dict[str, Any] | None = Field(default=None, description="AbuseIPDB reputation data if queried")


class InvestigationResponse(BaseModel):
    """Unified response representing the alert investigation playbook and enriched IOCs."""

    summary: str = Field(..., description="High-level investigation summary of findings")
    iocs: list[ExtractedIOC] = Field(default_factory=list, description="Extracted and enriched IOCs")
    recommended_investigation_steps: list[str] = Field(..., description="Step-by-step investigation playbook tasks")
    containment_actions: list[str] = Field(..., description="Recommended actions to contain the threat")
    recovery_actions: list[str] = Field(..., description="Recommended actions to recover from the incident")
    detection_recommendations: list[str] = Field(..., description="Recommended long-term rules/alerts for detection")
    confidence_score: int = Field(..., description="Overall confidence level of threat analysis from 0 to 100")
