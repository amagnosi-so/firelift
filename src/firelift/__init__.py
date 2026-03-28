"""Firelift: HTTP client for Prometheus-style scrape and query endpoints."""

from firelift.cli import (
    SLO_QUERIES,
    MetricSample,
    FireliftClient,
    FireliftClientError,
    prometheus_read_dump,
)

__all__ = [
    "SLO_QUERIES",
    "MetricSample",
    "FireliftClient",
    "FireliftClientError",
    "prometheus_read_dump",
]
__version__ = "0.1.0"
