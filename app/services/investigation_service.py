"""Security alert investigation service.

Purpose:
    Extract IOCs, enrich them with configured threat intel sources (VirusTotal, AbuseIPDB),
    and generate a SOC playbook using the configured Groq LLM.
"""

from dataclasses import dataclass
import json
from urllib.parse import urlparse
from typing import Any

from app.core.config import Settings
from app.schemas.alert import SecurityAlertRequest
from app.schemas.investigation import ExtractedIOC, InvestigationResponse
from app.schemas.integrations import ThreatIndicatorRequest
from app.services.indicator_extractor import IndicatorExtractor
from app.services.llm_client import OpenAIChatClient
from app.services.prompt_loader import PromptLoader


@dataclass(slots=True)
class InvestigationService:
    """Orchestrates security alert investigation, enrichment, and playbook generation."""

    settings: Settings
    extractor: IndicatorExtractor
    prompt_loader: PromptLoader

    @classmethod
    def from_settings(cls, settings: Settings) -> "InvestigationService":
        """Build the service from application settings."""
        return cls(
            settings=settings,
            extractor=IndicatorExtractor(),
            prompt_loader=PromptLoader(settings.prompt_directory),
        )

    def investigate(self, alert: SecurityAlertRequest) -> InvestigationResponse:
        """Perform enrichment and generate an investigation playbook for the alert."""
        content = f"{alert.title}\n{alert.description}"
        
        # 1. Extract IOCs
        ips = self.extractor.extract_ips(content)
        domains = self.extractor.extract_domains(content)
        urls = self.extractor.extract_urls(content)
        hashes = self.extractor.extract_hashes(content)
        usernames = self.extractor.extract_usernames(content)

        extracted_iocs: list[ExtractedIOC] = []
        enrichment_lines: list[str] = []

        # Setup services dynamically to prevent circular dependencies
        from app.services.virustotal_service import VirusTotalService
        from app.services.abuseipdb_service import AbuseIPDBService

        vt_service = None
        abuse_service = None

        try:
            vt_service = VirusTotalService(
                settings=self.settings,
                ai_service=None,  # Not needed for raw lookups
                extractor=self.extractor
            )
        except Exception:
            pass

        try:
            abuse_service = AbuseIPDBService(
                settings=self.settings,
                ai_service=None,  # Not needed for raw lookups
                extractor=self.extractor
            )
        except Exception:
            pass

        # 2. Enrich IPs
        for ip in ips:
            vt_data = None
            abuse_data = None
            
            if vt_service:
                try:
                    vt_res = vt_service.lookup(ThreatIndicatorRequest(indicator=ip))
                    if vt_res.status == "success":
                        vt_data = {
                            "malicious": vt_res.malicious,
                            "suspicious": vt_res.suspicious,
                            "reputation": vt_res.reputation,
                            "permalink": vt_res.permalink
                        }
                except Exception:
                    pass
            
            if abuse_service:
                try:
                    abuse_res = abuse_service.check_ip(ThreatIndicatorRequest(indicator=ip))
                    if abuse_res.status == "online":
                        abuse_data = {
                            "confidence_score": abuse_res.abuse_confidence_score,
                            "total_reports": abuse_res.total_reports,
                            "country_code": abuse_res.country_code,
                            "isp": abuse_res.isp
                        }
                except Exception:
                    pass

            extracted_iocs.append(ExtractedIOC(
                indicator=ip,
                indicator_type="ip",
                virustotal=vt_data,
                abuseipdb=abuse_data
            ))

            # Add to prompt enrichment context
            vt_info = f"VT Malicious={vt_data['malicious']}" if vt_data else "VT=Not Queried"
            abuse_info = f"Abuse Score={abuse_data['confidence_score']}" if abuse_data else "AbuseIPDB=Not Queried"
            enrichment_lines.append(f"- IP: {ip} ({vt_info}, {abuse_info})")

        # 3. Enrich Domains
        for domain in domains:
            vt_data = None
            if vt_service:
                try:
                    vt_res = vt_service.lookup(ThreatIndicatorRequest(indicator=domain))
                    if vt_res.status == "success":
                        vt_data = {
                            "malicious": vt_res.malicious,
                            "suspicious": vt_res.suspicious,
                            "reputation": vt_res.reputation,
                            "permalink": vt_res.permalink
                        }
                except Exception:
                    pass

            extracted_iocs.append(ExtractedIOC(
                indicator=domain,
                indicator_type="domain",
                virustotal=vt_data
            ))

            vt_info = f"VT Malicious={vt_data['malicious']}" if vt_data else "VT=Not Queried"
            enrichment_lines.append(f"- Domain: {domain} ({vt_info})")

        # 4. Enrich URLs (direct VT lookups)
        for url in urls:
            vt_data = None
            if vt_service:
                try:
                    vt_res = vt_service.lookup(ThreatIndicatorRequest(indicator=url))
                    if vt_res.status == "success":
                        vt_data = {
                            "malicious": vt_res.malicious,
                            "suspicious": vt_res.suspicious,
                            "reputation": vt_res.reputation,
                            "permalink": vt_res.permalink
                        }
                except Exception:
                    pass

            extracted_iocs.append(ExtractedIOC(
                indicator=url,
                indicator_type="url",
                virustotal=vt_data
            ))

            vt_info = f"VT Malicious={vt_data['malicious']}" if vt_data else "VT=Not Queried"
            enrichment_lines.append(f"- URL: {url} ({vt_info})")

        # 5. Enrich Hashes
        for file_hash in hashes:
            vt_data = None
            if vt_service:
                try:
                    vt_res = vt_service.lookup(ThreatIndicatorRequest(indicator=file_hash))
                    if vt_res.status == "success":
                        vt_data = {
                            "malicious": vt_res.malicious,
                            "suspicious": vt_res.suspicious,
                            "reputation": vt_res.reputation,
                            "permalink": vt_res.permalink
                        }
                except Exception:
                    pass

            extracted_iocs.append(ExtractedIOC(
                indicator=file_hash,
                indicator_type="file_hash",
                virustotal=vt_data
            ))

            vt_info = f"VT Malicious={vt_data['malicious']}" if vt_data else "VT=Not Queried"
            enrichment_lines.append(f"- Hash: {file_hash} ({vt_info})")

        # 6. Usernames (No dynamic enrichment, but cataloged)
        for username in usernames:
            extracted_iocs.append(ExtractedIOC(
                indicator=username,
                indicator_type="username"
            ))
            enrichment_lines.append(f"- Username: {username}")

        # 7. LLM Playbook Generation
        system_prompt = self.prompt_loader.load("security_investigation.md")
        
        enrichment_context = "\n".join(enrichment_lines) if enrichment_lines else "No IOCs found for enrichment."
        user_prompt = f"Security Alert:\n{json.dumps(alert.model_dump(), indent=2)}\n\nThreat Intelligence Enrichment:\n{enrichment_context}"

        # Initialize LLM client targeting Groq
        llm_client = OpenAIChatClient(
            api_key=self.settings.groq_api_key or "",
            model=self.settings.groq_model,
            base_url="https://api.groq.com/openai/v1",
        )

        model_response = llm_client.generate(system_prompt, user_prompt)

        # Strip markdown block wrappers if present
        cleaned = model_response.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        parsed = json.loads(cleaned)

        return InvestigationResponse(
            summary=parsed.get("summary", "No summary generated."),
            iocs=extracted_iocs,
            recommended_investigation_steps=parsed.get("recommended_investigation_steps", []),
            containment_actions=parsed.get("containment_actions", []),
            recovery_actions=parsed.get("recovery_actions", []),
            detection_recommendations=parsed.get("detection_recommendations", []),
            confidence_score=int(parsed.get("confidence_score", 50))
        )
