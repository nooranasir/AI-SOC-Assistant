"""Deterministic log analysis service.

Purpose:
    Analyze supported log families locally and convert them into the common
    security alert analysis shape used throughout the application.

Inputs:
    Typed log analysis requests.

Outputs:
    AlertAnalysisResponse models.

Dependencies:
    Regex matching, the MITRE mapper, and the alert analysis schema.
"""

from dataclasses import dataclass
import re

from app.schemas.alert import AlertAnalysisResponse
from app.schemas.logs import LogAnalysisRequest, SupportedLogType
from app.services.mitre_mapper import MitreMapper


@dataclass(slots=True)
class LogAnalyzer:
    """Analyze supported log formats using local heuristics."""

    mitre_mapper: MitreMapper

    def analyze(self, request: LogAnalysisRequest) -> AlertAnalysisResponse:
        """Analyze a supported log payload and return a structured response."""
        analysis = self._detect_pattern(request.log_type, request.content)
        mitre_mapping = self.mitre_mapper.map_text(
            f"{analysis['summary']} {analysis['threat_explanation']} {request.content}"
        )
        return AlertAnalysisResponse(
            alert_summary=analysis["summary"],
            severity=analysis["severity"],
            threat_explanation=analysis["threat_explanation"],
            mitre_technique=mitre_mapping.technique_name or analysis["mitre_technique"],
            mitre_tactic=mitre_mapping.tactic or analysis["mitre_tactic"],
            investigation_steps=analysis["investigation_steps"],
            recommended_response=analysis["recommended_response"],
            executive_summary=analysis["executive_summary"],
        )

    def _detect_pattern(self, log_type: SupportedLogType, content: str) -> dict[str, object]:
        """Detect the likely pattern for a supported log family."""
        normalized_content = content.lower()
        if log_type is SupportedLogType.windows_security:
            return self._analyze_windows_security(normalized_content)
        if log_type is SupportedLogType.linux_syslog:
            return self._analyze_linux_syslog(normalized_content)
        if log_type is SupportedLogType.apache:
            return self._analyze_apache_logs(normalized_content)
        return self._analyze_authentication_logs(normalized_content)

    def _analyze_windows_security(self, content: str) -> dict[str, object]:
        """Analyze Windows Security log patterns."""
        failed_logons = len(re.findall(r"failed logon|4625|failed password", content))
        successful_logons = len(re.findall(r"successful logon|4624|accepted password", content))
        if failed_logons >= 3 and successful_logons >= 1:
            return {
                "summary": "Repeated failed Windows logons followed by a successful login.",
                "severity": "high",
                "threat_explanation": "The pattern is consistent with password spraying or brute force activity against a Windows account.",
                "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "investigation_steps": [
                    "Check the targeted account for unusual activity.",
                    "Review the source host and authentication timestamps.",
                    "Confirm whether the successful login was expected.",
                ],
                "recommended_response": [
                    "Reset credentials if compromise is suspected.",
                    "Block the source of repeated failed logons.",
                    "Review authentication logs for additional suspicious access.",
                ],
                "executive_summary": "Windows authentication activity indicates a likely brute force attempt followed by a successful login.",
            }
        return {
            "summary": "Windows authentication activity requires review.",
            "severity": "medium",
            "threat_explanation": "The log indicates authentication activity that may be benign or suspicious depending on the broader context.",
            "mitre_technique": "Valid Accounts",
            "mitre_tactic": "Initial Access",
            "investigation_steps": [
                "Review the originating host and user account.",
                "Compare the activity with normal authentication behavior.",
                "Look for correlated endpoint or directory service alerts.",
            ],
            "recommended_response": [
                "Validate the login with the account owner.",
                "Increase monitoring for the account if behavior is unusual.",
            ],
            "executive_summary": "Windows authentication activity was detected and should be reviewed for legitimacy.",
        }

    def _analyze_linux_syslog(self, content: str) -> dict[str, object]:
        """Analyze Linux syslog authentication patterns."""
        failed_passwords = len(re.findall(r"failed password", content))
        accepted_passwords = len(re.findall(r"accepted password", content))
        if failed_passwords >= 2 and accepted_passwords >= 1:
            return {
                "summary": "Linux SSH failed-password attempts were followed by a successful login.",
                "severity": "high",
                "threat_explanation": "The sequence suggests password guessing or brute force activity against an SSH service.",
                "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "investigation_steps": [
                    "Identify the remote IP address and assess prior activity.",
                    "Review SSH logs for earlier failed attempts.",
                    "Confirm whether the successful login belongs to an approved user.",
                ],
                "recommended_response": [
                    "Restrict the source IP if unauthorized activity is confirmed.",
                    "Rotate credentials if compromise is suspected.",
                    "Harden SSH authentication controls.",
                ],
                "executive_summary": "Linux authentication logs indicate possible SSH brute force activity.",
            }
        return {
            "summary": "Linux authentication activity was detected.",
            "severity": "medium",
            "threat_explanation": "The authentication pattern warrants review for unusual or unauthorized access.",
            "mitre_technique": "Valid Accounts",
            "mitre_tactic": "Initial Access",
            "investigation_steps": [
                "Review the source IP and user account.",
                "Check for repeated failed authentication attempts.",
                "Correlate the event with other host activity.",
            ],
            "recommended_response": [
                "Verify the login with the account owner.",
                "Monitor for additional SSH authentication anomalies.",
            ],
            "executive_summary": "Linux authentication activity should be validated against expected behavior.",
        }

    def _analyze_apache_logs(self, content: str) -> dict[str, object]:
        """Analyze Apache access log patterns."""
        suspicious_paths = len(re.findall(r"/admin|/wp-admin|/login|/cgi-bin", content))
        server_errors = len(re.findall(r"\s500\s|\s404\s", content))
        if suspicious_paths >= 1 or server_errors >= 3:
            return {
                "summary": "Apache access logs contain suspicious targeting of web paths.",
                "severity": "high",
                "threat_explanation": "The log activity suggests reconnaissance or probing of web-facing application paths.",
                "mitre_technique": "Active Scanning",
                "mitre_tactic": "Reconnaissance",
                "investigation_steps": [
                    "Review the source IPs making the requests.",
                    "Check whether the targeted paths are expected.",
                    "Look for corresponding application errors or exploit attempts.",
                ],
                "recommended_response": [
                    "Block or rate-limit hostile traffic as appropriate.",
                    "Review web application hardening controls.",
                    "Validate that no sensitive resources were exposed.",
                ],
                "executive_summary": "Apache access logs indicate probing of web application paths.",
            }
        return {
            "summary": "Apache access activity appears low risk but should be reviewed.",
            "severity": "low",
            "threat_explanation": "The observed access pattern does not show strong signs of exploitation or scanning.",
            "mitre_technique": "Web Application Activity",
            "mitre_tactic": "Reconnaissance",
            "investigation_steps": [
                "Review request volume and user agents.",
                "Confirm the paths are part of expected usage.",
            ],
            "recommended_response": [
                "Continue monitoring access patterns.",
                "Baseline normal traffic for the application.",
            ],
            "executive_summary": "Apache access logs do not currently indicate strong malicious behavior.",
        }

    def _analyze_authentication_logs(self, content: str) -> dict[str, object]:
        """Analyze generic authentication logs."""
        failed_attempts = len(re.findall(r"failed|denied|invalid", content))
        successful_attempts = len(re.findall(r"success|accepted|granted", content))
        if failed_attempts > successful_attempts:
            return {
                "summary": "Authentication logs show more failures than successes.",
                "severity": "medium",
                "threat_explanation": "The balance of failures suggests possible credential abuse or account access issues.",
                "mitre_technique": "Brute Force",
                "mitre_tactic": "Credential Access",
                "investigation_steps": [
                    "Identify the affected user accounts.",
                    "Review source addresses and authentication timestamps.",
                    "Determine whether MFA was involved.",
                ],
                "recommended_response": [
                    "Validate account activity with the user.",
                    "Reset credentials if suspicious activity is confirmed.",
                ],
                "executive_summary": "Authentication logs suggest repeated access failures that should be investigated.",
            }
        return {
            "summary": "Authentication logs show standard access activity.",
            "severity": "low",
            "threat_explanation": "The log pattern does not show a clear sign of malicious authentication behavior.",
            "mitre_technique": "Valid Accounts",
            "mitre_tactic": "Initial Access",
            "investigation_steps": [
                "Confirm the activity matches approved access patterns.",
                "Keep monitoring for changes in failure rates or unusual logins.",
            ],
            "recommended_response": [
                "No immediate action required.",
                "Continue normal monitoring.",
            ],
            "executive_summary": "Authentication activity appears routine at this time.",
        }