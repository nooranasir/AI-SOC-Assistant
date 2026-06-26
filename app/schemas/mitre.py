"""Schemas for MITRE ATT&CK mapping endpoints.

Purpose:
    Provide typed request and response models for local MITRE lookups.

Inputs:
    Free-text alert context or technique identifiers.

Outputs:
    Structured MITRE mapping data.

Dependencies:
    pydantic for validation and schema generation.
"""

from pydantic import BaseModel, Field


class MitreMappingRequest(BaseModel):
    """Request body for local MITRE mapping."""

    text: str = Field(..., description="Alert text to map to MITRE ATT&CK")


class MitreTechniqueRecord(BaseModel):
    """Single MITRE ATT&CK technique record from the local mapping file."""

    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    technique_name: str = Field(..., description="MITRE ATT&CK technique name")
    tactic: str = Field(..., description="MITRE ATT&CK tactic")
    description: str = Field(..., description="Technique description")
    keywords: list[str] = Field(
        default_factory=list,
        description="Keywords used for local matching",
    )


class MitreMappingResponse(BaseModel):
    """Resolved MITRE mapping result."""

    technique_id: str | None = Field(default=None, description="Mapped technique ID")
    technique_name: str | None = Field(default=None, description="Mapped technique name")
    tactic: str | None = Field(default=None, description="Mapped MITRE tactic")
    description: str | None = Field(default=None, description="Mapped technique description")
    matched_keywords: list[str] = Field(
        default_factory=list,
        description="Keywords that triggered the match",
    )
    matched_on: str | None = Field(
        default=None,
        description="Match source such as technique_id or keywords",
    )
