"""Alert parsing and normalization utilities.

Purpose:
    Normalize raw JSON alert payloads from multiple sources (LetsDefend, Wazuh,
    Windows Event, Sysmon, and Generic SIEM) into the typed request model used
    across the application.

Inputs:
    Raw dictionaries, JSON strings, or lists of alerts from API clients.

Outputs:
    SecurityAlertRequest models.

Dependencies:
    json parsing and the security alert request schema.
"""

from collections.abc import Mapping
from dataclasses import dataclass
import json
from typing import Any

from app.schemas.alert import SecurityAlertRequest


class AlertValidationError(ValueError):
    """Exception raised when alert parsing or validation fails."""

    def __init__(self, message: str, missing_fields: list[str] = None):
        super().__init__(message)
        self.message = message
        self.missing_fields = missing_fields or []


@dataclass(slots=True)
class AlertParser:
    """Parse and normalize incoming security alert payloads from various formats."""

    def parse(self, payload: str | Mapping[str, Any] | list[Any]) -> SecurityAlertRequest:
        """Convert a raw payload into a validated security alert request."""
        alert_data = self._load_payload(payload)

        # 1. Detect format
        format_type = self._detect_format(alert_data)

        # 2. Extract based on format
        if format_type == "wazuh":
            normalized_alert = self._parse_wazuh(alert_data)
        elif format_type == "letsdefend":
            normalized_alert = self._parse_letsdefend(alert_data)
        elif format_type == "windows_event" or format_type == "sysmon":
            normalized_alert = self._parse_windows_event(alert_data, format_type)
        else:
            normalized_alert = self._parse_generic(alert_data)

        # 3. Check required fields and raise error if missing
        missing_fields = []
        required_fields = ["alert_id", "source", "title", "description"]
        for field in required_fields:
            val = normalized_alert.get(field)
            if val is None or not str(val).strip():
                # Try a fallback or register as missing
                if field == "alert_id":
                    normalized_alert["alert_id"] = f"GEN-ID-{hash(normalized_alert.get('title', '')) & 0xffffffff}"
                elif field == "source":
                    normalized_alert["source"] = "generic-siem"
                else:
                    missing_fields.append(field)

        if missing_fields:
            field_names = ", ".join(f"'{f}'" for f in missing_fields)
            raise AlertValidationError(
                message=f"Alert parsing failed: missing required fields {field_names}.",
                missing_fields=missing_fields
            )

        # Ensure all values are cleaned and stringified correctly
        return SecurityAlertRequest(
            alert_id=str(normalized_alert["alert_id"]).strip(),
            source=str(normalized_alert["source"]).strip(),
            title=str(normalized_alert["title"]).strip(),
            description=str(normalized_alert["description"]).strip(),
            severity=self._clean_severity(normalized_alert.get("severity")),
        )

    def _load_payload(self, payload: str | Mapping[str, Any] | list[Any]) -> dict[str, Any]:
        """Load a payload from JSON text, list, or mapping."""
        if isinstance(payload, str):
            try:
                loaded = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise AlertValidationError(f"Invalid JSON payload: {exc}")
            return self._load_payload(loaded)

        if isinstance(payload, list):
            if not payload:
                raise AlertValidationError("Alert payload is an empty list.")
            return self._load_payload(payload[0])

        if isinstance(payload, dict):
            # Check for Wazuh batch alerts wrapped in "alerts"
            if "alerts" in payload and isinstance(payload["alerts"], list):
                if not payload["alerts"]:
                    raise AlertValidationError("Alerts list wrapper is empty.")
                return self._load_payload(payload["alerts"][0])
            return payload

        raise AlertValidationError("Alert payload must decode to an object or a list of objects.")

    def _detect_format(self, data: dict[str, Any]) -> str:
        """Detect the security alert format from payload heuristics."""
        # Wazuh detection
        if "rule" in data and isinstance(data["rule"], dict) and ("description" in data["rule"] or "level" in data["rule"]):
            return "wazuh"

        # LetsDefend detection (EventID + Rule keys case-insensitively)
        keys_lower = {k.lower() for k in data.keys()}
        if "eventid" in keys_lower and any(r in keys_lower for r in ["rule", "rule name", "rule_name"]):
            return "letsdefend"

        # Windows Event & Sysmon detection
        has_event_nesting = "Event" in data and isinstance(data["Event"], dict)
        event_dict = data["Event"] if has_event_nesting else data
        if "System" in event_dict and isinstance(event_dict["System"], dict):
            provider_name = str(event_dict["System"].get("Provider", {}).get("Name", "")).lower()
            channel_name = str(event_dict["System"].get("Channel", "")).lower()
            if "sysmon" in provider_name or "sysmon" in channel_name:
                return "sysmon"
            return "windows_event"

        # Flat Sysmon detection
        if "CommandLine" in data or "ParentCommandLine" in data or "Image" in data:
            if "EventID" in data or "EventRecordID" in data:
                return "sysmon"

        return "generic"

    def _parse_wazuh(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize a Wazuh alert record."""
        rule = data.get("rule", {})
        agent = data.get("agent", {})
        decoder = data.get("decoder", {})

        title = self._first_val(rule.get("description"), decoder.get("name"), "Wazuh Alert")
        description = self._first_val(data.get("full_log"), data.get("data", {}).get("message"), title)
        alert_id = self._first_val(data.get("id"), rule.get("id"), "wazuh-alert")
        source = self._first_val(agent.get("name"), data.get("location"), "wazuh")

        return {
            "alert_id": alert_id,
            "source": source,
            "title": title,
            "description": description,
            "severity": rule.get("level"),
        }

    def _parse_letsdefend(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize a LetsDefend alert record."""
        # Find keys case-insensitively
        k_map = {k.lower(): k for k in data.keys()}

        def get_val(*keys: str) -> Any:
            for k in keys:
                if k.lower() in k_map:
                    return data[k_map[k.lower()]]
            return None

        alert_id = get_val("EventID", "eventId", "id")
        title = get_val("Rule", "Rule Name", "rule_name", "rule")
        severity = get_val("Severity", "level")
        event_time = get_val("Event Time", "eventTime", "Time")
        src_ip = get_val("Source IP", "sourceIP", "src_ip", "Source")
        dst_ip = get_val("Destination IP", "destinationIP", "dst_ip", "Destination")
        user = get_val("User", "username", "dstuser")
        action = get_val("Device Action", "action")

        desc_parts = [f"LetsDefend training alert triggered."]
        if event_time:
            desc_parts.append(f"Event Time: {event_time}.")
        if src_ip:
            desc_parts.append(f"Source IP: {src_ip}.")
        if dst_ip:
            desc_parts.append(f"Destination IP: {dst_ip}.")
        if user:
            desc_parts.append(f"Affected User: {user}.")
        if action:
            desc_parts.append(f"Device Action: {action}.")
        if "description" in k_map:
            desc_parts.append(f"Details: {data[k_map['description']]}")

        description = " ".join(desc_parts)

        return {
            "alert_id": alert_id,
            "source": "LetsDefend",
            "title": title,
            "description": description,
            "severity": severity,
        }

    def _parse_windows_event(self, data: dict[str, Any], detected_format: str) -> dict[str, Any]:
        """Normalize a Windows Event or Sysmon log."""
        event_block = data.get("Event", {}) if isinstance(data.get("Event"), dict) else data
        system = event_block.get("System", {}) if isinstance(event_block.get("System"), dict) else {}
        event_data = event_block.get("EventData", {}) if isinstance(event_block.get("EventData"), dict) else event_block.get("UserData", {})
        if not isinstance(event_data, dict):
            event_data = {}

        event_id = system.get("EventID") or data.get("EventID") or system.get("EventRecordID") or "unknown-id"
        channel = system.get("Channel") or "Windows-Event"
        provider = system.get("Provider", {}).get("Name") or "Microsoft-Windows-Security-Auditing"
        computer = system.get("Computer") or data.get("Computer") or "unknown-host"

        # Determine standard event titles
        titles = {
            4625: "Failed Logon Attempt",
            4624: "Successful Logon",
            4720: "User Account Created",
            7045: "New Service Installed",
            1: "Process Creation",
            3: "Network Connection Initiated",
            11: "File Created",
            22: "DNS Query Response",
        }
        event_name = titles.get(int(event_id)) if str(event_id).isdigit() else None
        
        prefix = "Sysmon" if detected_format == "sysmon" else "Windows"
        title = f"{prefix} Event {event_id}"
        if event_name:
            title += f" - {event_name}"

        # Build detailed description paragraph
        desc_parts = [f"{prefix} event log recorded on host '{computer}'. Provider: {provider}. EventID: {event_id}."]
        
        # Pull specific sysmon/windows parameters if available to build user-friendly description
        if detected_format == "sysmon" or int(event_id) in {1, 3, 11, 22}:
            image = event_data.get("Image") or data.get("Image")
            cmd = event_data.get("CommandLine") or data.get("CommandLine")
            user = event_data.get("User") or data.get("User")
            parent_cmd = event_data.get("ParentCommandLine") or data.get("ParentCommandLine")
            dest_ip = event_data.get("DestinationIp") or event_data.get("DestinationIP")
            dest_port = event_data.get("DestinationPort")
            query_name = event_data.get("QueryName")

            if user:
                desc_parts.append(f"User context: {user}.")
            if image:
                desc_parts.append(f"Image Path: {image}.")
            if cmd:
                desc_parts.append(f"Command executed: {cmd}.")
            if parent_cmd:
                desc_parts.append(f"Parent process command: {parent_cmd}.")
            if dest_ip:
                desc_parts.append(f"Network connection to IP: {dest_ip}:{dest_port or ''}.")
            if query_name:
                desc_parts.append(f"DNS Query: {query_name}.")
        
        # Fallback to appending all event data values
        details = []
        source_dict = event_data if event_data else data
        for k, v in source_dict.items():
            if k not in {"Image", "CommandLine", "User", "ParentCommandLine", "DestinationIp", "DestinationIP", "DestinationPort", "QueryName", "Event", "System", "EventData"}:
                if v is not None and str(v).strip():
                    details.append(f"{k}={v}")
        
        if details:
            desc_parts.append("Details: " + ", ".join(details) + ".")

        description = " ".join(desc_parts)
        
        # Severity mapping based on Windows System Level
        # Level 1: Critical, Level 2: Error, Level 3: Warning, Level 4: Information
        level = system.get("Level") or data.get("Level")
        severity = "low"
        if level is not None:
            try:
                lvl_num = int(level)
                if lvl_num == 1:
                    severity = "critical"
                elif lvl_num == 2:
                    severity = "high"
                elif lvl_num == 3:
                    severity = "medium"
            except (ValueError, TypeError):
                pass
        
        # Default security failures to medium
        if str(event_id) == "4625" and severity == "low":
            severity = "medium"

        return {
            "alert_id": event_id,
            "source": provider,
            "title": title,
            "description": description,
            "severity": severity,
        }

    def _parse_generic(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize a generic security alert JSON structure."""
        alert_id = self._find_field(data, ["alert_id", "alertId", "id", "uuid", "event_id", "eventId", "rule_id", "ruleId"])
        source = self._find_field(data, ["source", "provider", "vendor", "source_name", "system", "log_source"])
        title = self._find_field(data, ["title", "name", "summary", "rule_name", "ruleName", "subject"])
        description = self._find_field(data, ["description", "details", "message", "full_log", "msg", "text"])
        severity = self._find_field(data, ["severity", "level", "alert_severity", "priority"])

        # If description is missing, format all non-dict/list root elements as key-values
        if description is None or not str(description).strip():
            lines = []
            for k, v in data.items():
                if not isinstance(v, (dict, list)) and v is not None:
                    lines.append(f"{k}: {v}")
            if lines:
                description = "Generic Security Alert. Details: " + ", ".join(lines)

        return {
            "alert_id": alert_id,
            "source": source,
            "title": title,
            "description": description,
            "severity": severity,
        }

    def _find_field(self, d: dict[str, Any], target_keys: list[str]) -> Any:
        """Search for a value in a dictionary using a prioritized list of keys."""
        # 1. Search flat keys first
        for tk in target_keys:
            if tk in d and d[tk] is not None:
                val = d[tk]
                if isinstance(val, (dict, list)):
                    return json.dumps(val, indent=2)
                return str(val)
        
        # 2. Search nested keys recursively
        for k, v in d.items():
            if isinstance(v, dict):
                res = self._find_field(v, target_keys)
                if res is not None:
                    return res
        return None

    def _first_val(self, *values: Any) -> str:
        """Return the first non-empty string value."""
        for val in values:
            if val is not None:
                if isinstance(val, (dict, list)):
                    return json.dumps(val, indent=2)
                s = str(val).strip()
                if s:
                    return s
        return ""

    def _clean_severity(self, level: Any) -> str:
        """Normalize various severity inputs to standardized alert schema severity."""
        if level is None:
            return "medium"
        try:
            numeric_level = int(level)
            if numeric_level >= 12:
                return "critical"
            if numeric_level >= 9:
                return "high"
            if numeric_level >= 5:
                return "medium"
            return "low"
        except (ValueError, TypeError):
            val = str(level).strip().lower()
            if val in {"critical", "high", "medium", "low"}:
                return val
            if val.startswith("crit"):
                return "critical"
            if val.startswith("warn") or val.startswith("med"):
                return "medium"
            if val.startswith("info") or val.startswith("low"):
                return "low"
            if val.startswith("err") or val.startswith("hi"):
                return "high"
            return "medium"