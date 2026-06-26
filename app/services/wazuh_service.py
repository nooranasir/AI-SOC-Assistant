"""Wazuh integration service.

Purpose:
    Parse exported Wazuh alerts, convert them into the shared alert schema,
    send them through the AI analysis pipeline, and produce incident reports.

Inputs:
    Exported Wazuh alerts from alerts.json or direct API payloads.

Outputs:
    Normalized Wazuh analysis batches.

Dependencies:
    json parsing, the existing alert analysis service, MITRE mapper, and the
    report generator.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json

from app.core.config import Settings
from app.schemas.alert import SecurityAlertRequest
from app.schemas.integrations import WazuhAnalysisItem, WazuhBatchResponse
from app.schemas.report import IncidentReportRequest
from app.services.ai_service import AIAlertAnalysisService
from app.services.indicator_extractor import IndicatorExtractor
from app.services.mitre_mapper import MitreMapper
from app.services.report_generator import IncidentReportGenerator


@dataclass(slots=True)
class WazuhService:
    """Process exported Wazuh alerts through the security analysis pipeline."""

    settings: Settings
    ai_service: AIAlertAnalysisService
    mitre_mapper: MitreMapper
    report_generator: IncidentReportGenerator
    extractor: IndicatorExtractor

    @classmethod
    def from_settings(cls, settings: Settings, ai_service: AIAlertAnalysisService) -> "WazuhService":
        """Build the service from application settings."""
        return cls(
            settings=settings,
            ai_service=ai_service,
            mitre_mapper=MitreMapper(settings.mitre_mapping_path),
            report_generator=IncidentReportGenerator(settings.reports_directory),
            extractor=IndicatorExtractor(),
        )

    def process_payload(self, payload: Any, source_file: str = "alerts.json") -> WazuhBatchResponse:
        """Process a Wazuh export payload and return batch analysis results."""
        alerts = self._normalize_payload(payload)
        results: list[WazuhAnalysisItem] = []
        for record in alerts:
            parsed_alert = self._parse_record(record)
            mitre_mapping = self.mitre_mapper.map_text(
                f"{parsed_alert.title} {parsed_alert.description}"
            )
            enrichment_context = self._build_enrichment_context(record, mitre_mapping)
            analysis = self.ai_service.analyze(parsed_alert, enrichment_context=enrichment_context)
            report = self.report_generator.generate(
                IncidentReportRequest(
                    alert=parsed_alert,
                    analysis=analysis,
                    timeline=self._build_timeline(record),
                    indicators_of_compromise=self._build_iocs(record),
                )
            )
            results.append(
                WazuhAnalysisItem(
                    source_alert=record,
                    parsed_alert=parsed_alert,
                    mitre_mapping=mitre_mapping,
                    analysis=analysis,
                    report=report,
                )
            )
        return WazuhBatchResponse(source_file=source_file, alert_count=len(results), results=results)

    def load_sample(self) -> WazuhBatchResponse:
        """Load and process the bundled Wazuh sample export."""
        sample_path = self.settings.wazuh_sample_alerts_path
        return self.process_file(sample_path)

    def process_file(self, file_path: Path) -> WazuhBatchResponse:
        """Read and process an exported Wazuh alerts file from disk."""
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        return self.process_payload(payload, source_file=str(file_path))

    def _normalize_payload(self, payload: Any) -> list[dict[str, Any]]:
        """Normalize Wazuh payloads into a list of event records."""
        if isinstance(payload, list):
            return [self._ensure_mapping(item) for item in payload]
        if isinstance(payload, dict):
            if "alerts" in payload and isinstance(payload["alerts"], list):
                return [self._ensure_mapping(item) for item in payload["alerts"]]
            return [self._ensure_mapping(payload)]
        raise ValueError("Wazuh payload must be a mapping or list of mappings.")

    def _ensure_mapping(self, payload: Any) -> dict[str, Any]:
        """Ensure the Wazuh payload is a dictionary."""
        if not isinstance(payload, dict):
            raise ValueError("Each Wazuh alert must be a mapping.")
        return payload

    def _parse_record(self, record: dict[str, Any]) -> SecurityAlertRequest:
        """Convert a Wazuh event record into the shared alert schema."""
        title = self._first_value(
            record.get("rule", {}).get("description"),
            record.get("decoder", {}).get("name"),
            record.get("syscheck", {}).get("path"),
            "Wazuh alert",
        )
        description = self._first_value(
            record.get("full_log"),
            record.get("data", {}).get("message"),
            record.get("rule", {}).get("description"),
            title,
        )
        severity = self._normalize_severity(record.get("rule", {}).get("level"))
        alert_id = self._first_value(
            record.get("id"),
            record.get("rule", {}).get("id"),
            record.get("agent", {}).get("id"),
            title,
        )
        source = self._first_value(
            record.get("agent", {}).get("name"),
            record.get("manager", {}).get("name"),
            record.get("location"),
            "wazuh",
        )
        return SecurityAlertRequest(
            alert_id=str(alert_id),
            source=str(source),
            title=str(title),
            description=str(description),
            severity=severity,
        )

    def _build_enrichment_context(self, record: dict[str, Any], mitre_mapping: Any) -> str:
        """Build enrichment context for the AI analysis service."""
        parts = [
            f"Wazuh rule: {record.get('rule', {}).get('description', 'unknown')}",
            f"Wazuh level: {record.get('rule', {}).get('level', 'unknown')}",
        ]
        if mitre_mapping.technique_name:
            parts.append(
                f"Local MITRE mapping: {mitre_mapping.technique_id} {mitre_mapping.technique_name} ({mitre_mapping.tactic})"
            )
        iocs = self._build_iocs(record)
        if iocs:
            parts.append(f"Observed indicators: {', '.join(iocs)}")
        return "\n".join(parts)

    def _build_timeline(self, record: dict[str, Any]) -> list[str]:
        """Build a simple timeline for the report generator."""
        timeline: list[str] = []
        if timestamp := record.get("timestamp"):
            timeline.append(f"{timestamp}: Wazuh alert recorded")
        if rule_description := record.get("rule", {}).get("description"):
            timeline.append(f"Rule triggered: {rule_description}")
        return timeline

    def _build_iocs(self, record: dict[str, Any]) -> list[str]:
        """Extract indicators of compromise from the alert record."""
        content = json.dumps(record)
        indicators = []
        indicators.extend(self.extractor.extract_ips(content))
        indicators.extend(self.extractor.extract_domains(content))
        indicators.extend(self.extractor.extract_hashes(content))
        return indicators

    def _normalize_severity(self, level: Any) -> str | None:
        """Convert a Wazuh numeric severity into a friendly label."""
        if level is None:
            return None
        try:
            numeric_level = int(level)
        except (TypeError, ValueError):
            return str(level)
        if numeric_level >= 12:
            return "critical"
        if numeric_level >= 9:
            return "high"
        if numeric_level >= 5:
            return "medium"
        return "low"

    def _first_value(self, *values: Any) -> Any:
        """Return the first non-empty value from the supplied values."""
        for value in values:
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            return value
        return "unknown"
