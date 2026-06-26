"""Schemas for incident report generation.

Purpose:
    Define the FastAPI request and response models for incident report output.

Inputs:
    Alert analysis results and optional incident context.

Outputs:
    Structured incident report payloads.

Dependencies:
    pydantic for schema validation and datetime support.
"""

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, Field

from app.schemas.alert import AlertAnalysisResponse, SecurityAlertRequest


class IncidentReportRequest(BaseModel):
    """Request body for generating an incident report."""

    alert: SecurityAlertRequest = Field(..., description="Original security alert")
    analysis: AlertAnalysisResponse = Field(..., description="LLM analysis result")
    timeline: list[str] = Field(
        default_factory=list,
        description="Chronological incident observations",
    )
    indicators_of_compromise: list[str] = Field(
        default_factory=list,
        description="Observed indicators of compromise",
    )


class IncidentReportResponse(BaseModel):
    """Structured incident report response."""

    report_id: str = Field(default_factory=lambda: str(uuid4()), description="Report ID")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Generation time")
    alert_summary: str = Field(..., description="Alert summary")
    severity: str = Field(..., description="Normalized severity")
    threat_explanation: str = Field(..., description="Threat explanation")
    mitre_technique: str = Field(..., description="Mapped MITRE technique")
    mitre_tactic: str = Field(..., description="Mapped MITRE tactic")
    timeline: list[str] = Field(..., description="Chronological incident observations")
    indicators_of_compromise: list[str] = Field(..., description="Observed indicators of compromise")
    root_cause: str = Field(..., description="Likely root cause")
    recommended_actions: list[str] = Field(..., description="Recommended response actions")
    executive_summary: str = Field(..., description="Executive summary")
    report_markdown: str = Field(..., description="Rendered markdown report")
