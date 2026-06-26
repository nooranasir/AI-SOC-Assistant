"""Incident report generation service.

Purpose:
    Convert alert analysis results into a professional incident report using an
    editable markdown template.

Inputs:
    IncidentReportRequest models.

Outputs:
    IncidentReportResponse models.

Dependencies:
    pathlib for template loading and the incident report schemas.
"""

from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone

from app.schemas.report import IncidentReportRequest, IncidentReportResponse


@dataclass(slots=True)
class IncidentReportGenerator:
    """Generate incident reports from alert analysis data."""

    reports_directory: Path

    def generate(self, request: IncidentReportRequest) -> IncidentReportResponse:
        """Generate a structured report and a rendered markdown document."""
        template = self._load_template()
        timeline = request.timeline
        indicators_of_compromise = request.indicators_of_compromise
        root_cause = self._derive_root_cause(request)
        report_markdown = template.format(
            report_title=f"Incident Report: {request.alert.title}",
            alert_id=request.alert.alert_id,
            source=request.alert.source,
            alert_summary=request.analysis.alert_summary,
            severity=request.analysis.severity,
            threat_explanation=request.analysis.threat_explanation,
            mitre_technique=request.analysis.mitre_technique,
            mitre_tactic=request.analysis.mitre_tactic,
            timeline=self._format_bullets(timeline),
            indicators_of_compromise=self._format_bullets(indicators_of_compromise),
            root_cause=root_cause,
            recommended_actions=self._format_bullets(
                request.analysis.recommended_response
            ),
            executive_summary=request.analysis.executive_summary,
        )

        return IncidentReportResponse(
            alert_summary=request.analysis.alert_summary,
            severity=request.analysis.severity,
            threat_explanation=request.analysis.threat_explanation,
            mitre_technique=request.analysis.mitre_technique,
            mitre_tactic=request.analysis.mitre_tactic,
            timeline=timeline,
            indicators_of_compromise=indicators_of_compromise,
            root_cause=root_cause,
            recommended_actions=request.analysis.recommended_response,
            executive_summary=request.analysis.executive_summary,
            report_markdown=report_markdown,
            generated_at=datetime.now(timezone.utc),
        )

    def _load_template(self) -> str:
        """Load the markdown report template from disk."""
        template_path = self.reports_directory / "incident_report_template.md"
        return template_path.read_text(encoding="utf-8")

    def _derive_root_cause(self, request: IncidentReportRequest) -> str:
        """Derive a concise likely root cause statement."""
        return (
            f"Activity consistent with {request.analysis.mitre_technique} "
            f"impacting {request.alert.source}."
        )

    def _format_bullets(self, items: list[str]) -> str:
        """Format a list of items as markdown bullets."""
        if not items:
            return "- Not provided"
        return "\n".join(f"- {item}" for item in items)