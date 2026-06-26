"""Local MITRE ATT&CK mapping service.

Purpose:
    Load MITRE ATT&CK techniques from the repository's JSON data file and
    perform deterministic text matching without using external services.

Inputs:
    Free-text alert context or MITRE technique identifiers.

Outputs:
    Structured MITRE mapping results.

Dependencies:
    pathlib, json, and the MITRE schemas.
"""

from dataclasses import dataclass
import json
from pathlib import Path

from app.schemas.mitre import MitreMappingResponse, MitreTechniqueRecord


@dataclass(slots=True)
class MitreMapper:
    """Resolve MITRE ATT&CK techniques from a local JSON file."""

    mapping_path: Path

    def list_techniques(self) -> list[MitreTechniqueRecord]:
        """Return all MITRE technique records from the local mapping file."""
        mapping_data = self._load_mapping()
        return [MitreTechniqueRecord.model_validate(item) for item in mapping_data]

    def map_text(self, text: str) -> MitreMappingResponse:
        """Map free text to the best matching MITRE technique."""
        normalized_text = text.lower()
        best_record: MitreTechniqueRecord | None = None
        best_keywords: list[str] = []
        best_score = 0

        for record in self.list_techniques():
            current_keywords: list[str] = []
            score = 0
            if record.technique_id.lower() in normalized_text:
                score += 2
            for keyword in record.keywords:
                if keyword.lower() in normalized_text:
                    current_keywords.append(keyword)
                    score += 1
            if score > best_score:
                best_record = record
                best_keywords = current_keywords
                best_score = score

        if best_record is None or best_score == 0:
            return MitreMappingResponse()

        return MitreMappingResponse(
            technique_id=best_record.technique_id,
            technique_name=best_record.technique_name,
            tactic=best_record.tactic,
            description=best_record.description,
            matched_keywords=best_keywords,
            matched_on="keywords" if best_keywords else "technique_id",
        )

    def _load_mapping(self) -> list[dict[str, object]]:
        """Load the raw mapping file and return the technique collection."""
        mapping_content = self.mapping_path.read_text(encoding="utf-8")
        mapping_data = json.loads(mapping_content)
        techniques = mapping_data.get("techniques", [])
        if not isinstance(techniques, list):
            raise ValueError("MITRE mapping file must contain a techniques list.")
        return techniques