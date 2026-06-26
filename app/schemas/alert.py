"""Request and response schemas for security alert analysis.

Purpose:
    Define the FastAPI-facing models for future alert analysis endpoints.

Inputs:
    Security alert payloads submitted by API clients.

Outputs:
    Structured analysis responses returned by the application.

Dependencies:
    pydantic for data validation and schema generation.
"""

from pydantic import BaseModel, Field


class SecurityAlertRequest(BaseModel):
    """Incoming security alert payload."""

    alert_id: str = Field(..., description="Unique identifier for the alert")
    source: str = Field(..., description="Source system that produced the alert")
    title: str = Field(..., description="Short alert title")
    description: str = Field(..., description="Detailed alert description")
    severity: str | None = Field(default=None, description="Source-provided severity")


class AlertAnalysisResponse(BaseModel):
    """Structured alert analysis response."""

    alert_summary: str = Field(..., description="Short summary of the alert")
    severity: str = Field(..., description="Normalized severity level")
    threat_explanation: str = Field(..., description="Plain-English threat explanation")
    mitre_technique: str = Field(..., description="MITRE ATT&CK technique")
    mitre_tactic: str = Field(..., description="MITRE ATT&CK tactic")
    investigation_steps: list[str] = Field(..., description="Analyst investigation steps")
    recommended_response: list[str] = Field(..., description="Recommended response actions")
    executive_summary: str = Field(..., description="Executive-friendly summary")
