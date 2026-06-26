"""Schemas for sample log loading endpoints.

Purpose:
    Provide typed API responses for sample log discovery and retrieval.

Inputs:
    Sample log names and file content.

Outputs:
    FastAPI response models.

Dependencies:
    pydantic for request and response modeling.
"""

from enum import Enum

from pydantic import BaseModel, Field


class SupportedLogType(str, Enum):
    """Supported log families for local analysis."""

    windows_security = "windows_security"
    linux_syslog = "linux_syslog"
    apache = "apache"
    authentication = "authentication"


class SampleLogListResponse(BaseModel):
    """List of available sample log files."""

    sample_logs: list[str] = Field(..., description="Available sample log file names")


class SampleLogContentResponse(BaseModel):
    """Content of a loaded sample log file."""

    file_name: str = Field(..., description="Sample log file name")
    content: str = Field(..., description="Raw sample log content")


class LogAnalysisRequest(BaseModel):
    """Request body for analyzing raw logs."""

    log_type: SupportedLogType = Field(..., description="Type of log to analyze")
    content: str = Field(..., description="Raw log content")
