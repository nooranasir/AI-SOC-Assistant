"""Application configuration backed by environment variables."""

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
import os

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")
PROMPTS_DIR = BASE_DIR / "prompts"
DATA_DIR = BASE_DIR / "data"
MITRE_DIR = DATA_DIR / "mitre"
LOGS_DIR = BASE_DIR / "logs"
SAMPLE_LOGS_DIR = LOGS_DIR / "samples"
REPORTS_DIR = BASE_DIR / "reports"
WAZUH_SAMPLE_ALERTS_PATH = SAMPLE_LOGS_DIR / "wazuh" / "alerts.json"


@dataclass(frozen=True, slots=True)
class Settings:
    """Application settings loaded from environment variables."""

    app_name: str = os.getenv("APP_NAME", "AI SOC Assistant")
    app_version: str = os.getenv("APP_VERSION", "1.0.0")
    app_env: str = os.getenv("APP_ENV", "development")
    cors_origins: list[str] = field(default_factory=lambda: [
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174,http://localhost:5175,http://127.0.0.1:5175,null",
        ).split(",")
        if origin.strip()
    ])
    llm_provider: str = os.getenv("LLM_PROVIDER", "groq")
    groq_api_key: str | None = os.getenv("GROQ_API_KEY")
    groq_model: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    virustotal_api_key: str | None = os.getenv("VIRUSTOTAL_API_KEY")
    virustotal_base_url: str = os.getenv(
        "VIRUSTOTAL_BASE_URL",
        "https://www.virustotal.com/api/v3",
    )
    abuseipdb_api_key: str | None = os.getenv("ABUSEIPDB_API_KEY")
    elasticsearch_url: str | None = os.getenv("ELASTICSEARCH_URL")
    elasticsearch_username: str | None = os.getenv("ELASTICSEARCH_USERNAME")
    elasticsearch_password: str | None = os.getenv("ELASTICSEARCH_PASSWORD")
    elasticsearch_api_key: str | None = os.getenv("ELASTICSEARCH_API_KEY")
    elasticsearch_alerts_index: str = os.getenv("ELASTICSEARCH_ALERTS_INDEX", "alerts")
    elasticsearch_logs_index: str = os.getenv("ELASTICSEARCH_LOGS_INDEX", "logs")
    mitre_mapping_path: Path = Path(
        os.getenv("MITRE_MAPPING_PATH", str(MITRE_DIR / "mitre_mapping.json"))
    )
    prompt_directory: Path = PROMPTS_DIR
    sample_logs_directory: Path = SAMPLE_LOGS_DIR
    reports_directory: Path = REPORTS_DIR
    wazuh_sample_alerts_path: Path = WAZUH_SAMPLE_ALERTS_PATH


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached settings instance."""
    return Settings()
