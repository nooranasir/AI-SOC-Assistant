"""API route definitions for AI SOC Assistant."""

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from app.core.config import get_settings
from app.schemas.alert import AlertAnalysisResponse, SecurityAlertRequest
from app.schemas.investigation import InvestigationResponse
from app.schemas.logs import LogAnalysisRequest, SampleLogContentResponse, SampleLogListResponse
from app.schemas.mitre import MitreMappingRequest, MitreMappingResponse, MitreTechniqueRecord
from app.schemas.report import IncidentReportRequest, IncidentReportResponse
from app.services.alert_parser import AlertParser, AlertValidationError
from app.services.ai_service import AIAlertAnalysisService
from app.services.investigation_service import InvestigationService
from app.services.log_analyzer import LogAnalyzer
from app.services.mitre_mapper import MitreMapper
from app.services.report_generator import IncidentReportGenerator
from app.services.sample_log_loader import SampleLogLoader

router = APIRouter()


def get_alert_analysis_service() -> AIAlertAnalysisService:
    """Create the alert analysis service from application settings."""
    return AIAlertAnalysisService.from_settings(get_settings())


def get_investigation_service() -> InvestigationService:
    """Create the investigation service from application settings."""
    return InvestigationService.from_settings(get_settings())


def get_alert_parser() -> AlertParser:
    """Create the alert parser dependency."""
    return AlertParser()


def get_sample_log_loader() -> SampleLogLoader:
    """Create the sample log loader dependency."""
    settings = get_settings()
    return SampleLogLoader(settings.sample_logs_directory)


def get_log_analyzer() -> LogAnalyzer:
    """Create the log analyzer dependency."""
    settings = get_settings()
    return LogAnalyzer(MitreMapper(settings.mitre_mapping_path))


def get_mitre_mapper() -> MitreMapper:
    """Create the MITRE mapper dependency."""
    settings = get_settings()
    return MitreMapper(settings.mitre_mapping_path)


def get_report_generator() -> IncidentReportGenerator:
    """Create the incident report generator dependency."""
    settings = get_settings()
    return IncidentReportGenerator(settings.reports_directory)


@router.get("/health", tags=["health"])
async def health_check() -> dict[str, str]:
    """Return the service health status."""
    return {"status": "ok", "service": "ai-soc-assistant"}


@router.post(
    "/alerts/parse",
    response_model=SecurityAlertRequest,
    tags=["analysis"],
)
async def parse_alert(
    payload: dict[str, Any] = Body(...),
    parser: AlertParser = Depends(get_alert_parser),
) -> SecurityAlertRequest:
    """Parse a raw JSON alert into the typed request model."""
    try:
        return parser.parse(payload)
    except AlertValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Validation Failed",
                "message": exc.message,
                "missing_fields": exc.missing_fields,
                "supported_formats": [
                    "LetsDefend alerts",
                    "Wazuh exported alerts",
                    "Windows Event JSON",
                    "Sysmon JSON",
                    "Generic SIEM JSON"
                ]
            }
        )


@router.post(
    "/alerts/analyze",
    response_model=AlertAnalysisResponse,
    tags=["analysis"],
)
async def analyze_alert(
    alert: SecurityAlertRequest,
    service: AIAlertAnalysisService = Depends(get_alert_analysis_service),
) -> AlertAnalysisResponse:
    """Analyze an incoming security alert with the configured LLM."""
    import openai
    import json
    try:
        return service.analyze(alert)
    except openai.AuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail=f"LLM authentication failed. Please verify your GROQ_API_KEY configuration. Details: {exc}"
        )
    except openai.OpenAIError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"The AI analysis server encountered an issue. Details: {exc}"
        )
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"The AI analysis server returned a malformed response that could not be parsed as JSON. Details: {exc}"
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred during alert analysis. Details: {str(exc)}"
        )


@router.post(
    "/alerts/investigate",
    response_model=InvestigationResponse,
    tags=["investigation"],
)
async def investigate_alert(
    alert: SecurityAlertRequest,
    service: InvestigationService = Depends(get_investigation_service),
) -> InvestigationResponse:
    """Perform enrichment and generate a SOC investigation playbook for the alert."""
    import openai
    import json
    try:
        return service.investigate(alert)
    except openai.AuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail=f"LLM authentication failed. Please verify your GROQ_API_KEY configuration. Details: {exc}"
        )
    except openai.OpenAIError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"The AI investigation server encountered an issue. Details: {exc}"
        )
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"The AI investigation server returned a malformed playbook response that could not be parsed as JSON. Details: {exc}"
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred during alert investigation. Details: {str(exc)}"
        )


@router.get(
    "/logs/samples",
    response_model=SampleLogListResponse,
    tags=["logs"],
)
async def list_sample_logs(
    loader: SampleLogLoader = Depends(get_sample_log_loader),
) -> SampleLogListResponse:
    """List the available sample log files."""
    return SampleLogListResponse(sample_logs=loader.list_sample_logs())


@router.get(
    "/logs/samples/{sample_name}",
    response_model=SampleLogContentResponse,
    tags=["logs"],
)
async def load_sample_log(
    sample_name: str,
    loader: SampleLogLoader = Depends(get_sample_log_loader),
) -> SampleLogContentResponse:
    """Return the contents of a named sample log file."""
    return SampleLogContentResponse(
        file_name=sample_name,
        content=loader.load(sample_name),
    )


@router.get(
    "/mitre/techniques",
    response_model=list[MitreTechniqueRecord],
    tags=["mitre"],
)
async def list_mitre_techniques(
    mapper: MitreMapper = Depends(get_mitre_mapper),
) -> list[MitreTechniqueRecord]:
    """List all locally configured MITRE ATT&CK techniques."""
    return mapper.list_techniques()


@router.post(
    "/mitre/map",
    response_model=MitreMappingResponse,
    tags=["mitre"],
)
async def map_mitre_technique(
    request: MitreMappingRequest,
    mapper: MitreMapper = Depends(get_mitre_mapper),
) -> MitreMappingResponse:
    """Map free text to the best matching local MITRE ATT&CK technique."""
    return mapper.map_text(request.text)


@router.post(
    "/reports/incidents",
    response_model=IncidentReportResponse,
    tags=["reports"],
)
async def generate_incident_report(
    request: IncidentReportRequest,
    generator: IncidentReportGenerator = Depends(get_report_generator),
) -> IncidentReportResponse:
    """Generate a markdown incident report from analysis data."""
    return generator.generate(request)


@router.post(
    "/logs/analyze",
    response_model=AlertAnalysisResponse,
    tags=["logs"],
)
async def analyze_log(
    request: LogAnalysisRequest,
    analyzer: LogAnalyzer = Depends(get_log_analyzer),
) -> AlertAnalysisResponse:
    """Analyze a supported raw log payload."""
    return analyzer.analyze(request)


@router.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    """Return a simple welcome message for the API root."""
    return {"message": "AI SOC Assistant API is running."}
