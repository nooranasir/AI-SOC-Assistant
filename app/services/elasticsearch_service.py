"""Elasticsearch integration service.

Purpose:
    Search alert and log indices over the Elasticsearch REST API and normalize
    the search results for API consumers. Disabled for version 1.

Inputs:
    Search queries and configured index names.

Outputs:
    Normalized Elasticsearch search results.

Dependencies:
    requests for HTTPS API calls.
"""

from dataclasses import dataclass
from typing import Any

from app.core.config import Settings
from app.schemas.integrations import ElasticsearchSearchHit, ElasticsearchSearchResponse


@dataclass(slots=True)
class ElasticsearchService:
    """Query Elasticsearch using the REST API (disabled for version 1)."""

    settings: Settings

    @classmethod
    def from_settings(cls, settings: Settings) -> "ElasticsearchService":
        """Build the service from application settings."""
        return cls(settings=settings)

    def search_alerts(self, query: str, size: int = 10) -> ElasticsearchSearchResponse:
        """Search the alerts index."""
        return self.search(self.settings.elasticsearch_alerts_index, query, size=size)

    def search_logs(self, query: str, size: int = 10) -> ElasticsearchSearchResponse:
        """Search the logs index."""
        return self.search(self.settings.elasticsearch_logs_index, query, size=size)

    def search(self, index: str, query: str, size: int = 10) -> ElasticsearchSearchResponse:
        """Run a search query (always offline in this version)."""
        return ElasticsearchSearchResponse(
            query=query,
            index=index,
            total=0,
            hits=[],
            raw_response={},
            status="offline",
            message="Elasticsearch is not configured."
        )
