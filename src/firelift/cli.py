"""Firelift: HTTP client for Prometheus exposition (/metrics) and compatible query APIs.

Typical targets expose Prometheus text on ``/metrics`` and answer instant queries at
``/api/v1/query`` (for example Prometheus or Thanos on port 9090).

Use the same host:port your target listens on:
  - Scrape text: GET http(s)://host:PORT/metrics
  - Instant queries: GET http(s)://host:PORT/api/v1/query?query=...

HTTPS uses TLS with **certificate verification off by default** (self-signed friendly); pass
``verify_ssl=True`` (API) or ``--verify-ssl`` (CLI) to enforce normal verification.

Only the Python standard library is required.

Command-line: ``firelift --help`` or ``python -m firelift --help``.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass
from typing import Any, Iterator, Mapping, Optional, Sequence, Union

QueryParam = Union[Mapping[str, str], Sequence[tuple[str, str]]]


def _suppress_tls_insecurity_warnings() -> None:
    """Quiet common libraries when certificate verification is disabled."""
    warnings.filterwarnings("ignore", message=".*Unverified HTTPS request.*")
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass


_suppress_tls_insecurity_warnings()

# (exported SLO metric name, window) -> PromQL for instant query at /api/v1/query
SLO_QUERIES: Mapping[tuple[str, str], str] = {
    ("cluster_slo_replica_eviction_ratio", "1h"): "cluster:replica_eviction_ratio:sum1h",
    ("cluster_slo_replica_eviction_ratio", "24h"): "cluster:replica_eviction_ratio:sum24h",
    ("cluster_slo_replica_eviction_ratio", "7d"): "cluster:replica_eviction_ratio:sum7d",
    ("cluster_slo_external_scheduling_latency_p99_sli", "1h"): "cluster:external_scheduling_latency_p99_sli:avg1h",
    ("cluster_slo_external_scheduling_latency_p99_sli", "24h"): "cluster:external_scheduling_latency_p99_sli:avg24h",
    ("cluster_slo_external_scheduling_latency_p99_sli", "7d"): "cluster:external_scheduling_latency_p99_sli:avg7d",
    ("cluster_slo_external_system_availability_sli", "1h"): "cluster:external_system_availability_sli:avg1h",
    ("cluster_slo_external_system_availability_sli", "24h"): "cluster:external_system_availability_sli:avg24h",
    ("cluster_slo_external_system_availability_sli", "7d"): "cluster:external_system_availability_sli:avg7d",
    (
        "cluster_slo_namespace_job_failed_node_unhealthy",
        "1h",
    ): "count(namespace_job_failed:node_unhealthy:increase1h) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_node_unhealthy",
        "24h",
    ): "count(namespace_job_failed:node_unhealthy:increase24h) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_node_unhealthy",
        "7d",
    ): "count(namespace_job_failed:node_unhealthy:increase7d) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_node_nic_error",
        "1h",
    ): "count(namespace_job_failed:node_nic_error:increase1h) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_node_nic_error",
        "24h",
    ): "count(namespace_job_failed:node_nic_error:increase24h) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_node_nic_error",
        "7d",
    ): "count(namespace_job_failed:node_nic_error:increase7d) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_system_unhealthy",
        "1h",
    ): "count(namespace_job_failed:system_unhealthy:increase1h) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_system_unhealthy",
        "24h",
    ): "count(namespace_job_failed:system_unhealthy:increase24h) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_system_unhealthy",
        "7d",
    ): "count(namespace_job_failed:system_unhealthy:increase7d) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_system_port_error",
        "1h",
    ): "count(namespace_job_failed:system_port_error:increase1h) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_system_port_error",
        "24h",
    ): "count(namespace_job_failed:system_port_error:increase24h) or vector(0)",
    (
        "cluster_slo_namespace_job_failed_system_port_error",
        "7d",
    ): "count(namespace_job_failed:system_port_error:increase7d) or vector(0)",
}

_METRIC_LINE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?P<labels>\{[^}]*\})?\s+"
    r"(?P<value>(?:NaN|[-+]?Infinity|[-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?))"
    r"(?:\s+(?P<ts>[0-9]+))?\s*$"
)


class FireliftClientError(Exception):
    """Request failed or response could not be interpreted."""


@dataclass(frozen=True)
class MetricSample:
    name: str
    labels: dict[str, str]
    value: float
    timestamp_ms: Optional[int] = None


class FireliftClient:
    """HTTP client for a Prometheus scrape endpoint (/metrics) and/or query API (/api/v1/query)."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:9090",
        timeout_seconds: float = 5.0,
        *,
        verify_ssl: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = max(timeout_seconds, 0.001)
        self.verify_ssl = verify_ssl
        if verify_ssl:
            self._ssl_context: Optional[ssl.SSLContext] = None
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._ssl_context = ctx

    def _get(self, path: str, query: Optional[QueryParam] = None) -> bytes:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.base_url}{path}"
        if query is not None:
            if isinstance(query, Mapping):
                qstr = urllib.parse.urlencode(dict(query))
            else:
                qstr = urllib.parse.urlencode(list(query), doseq=True)
            url = f"{url}?{qstr}"
        try:
            with urllib.request.urlopen(
                url,
                timeout=self.timeout_seconds,
                context=self._ssl_context,
            ) as response:
                return response.read()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise FireliftClientError(f"HTTP {e.code} for {url}: {body}") from e
        except urllib.error.URLError as e:
            raise FireliftClientError(f"request failed for {url}: {e}") from e

    def _post(self, path: str, query: Optional[QueryParam] = None, data: Optional[bytes] = None) -> bytes:
        """HTTP POST *path*; body defaults to empty (Prometheus admin snapshot uses empty POST)."""
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.base_url}{path}"
        if query is not None:
            if isinstance(query, Mapping):
                qstr = urllib.parse.urlencode(dict(query))
            else:
                qstr = urllib.parse.urlencode(list(query), doseq=True)
            url = f"{url}?{qstr}"
        payload = data if data is not None else b""
        req = urllib.request.Request(url, data=payload, method="POST")
        try:
            with urllib.request.urlopen(
                req,
                timeout=self.timeout_seconds,
                context=self._ssl_context,
            ) as response:
                return response.read()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise FireliftClientError(f"HTTP {e.code} for {url}: {body}") from e
        except urllib.error.URLError as e:
            raise FireliftClientError(f"request failed for {url}: {e}") from e

    def post_json(self, path: str, query: Optional[QueryParam] = None, data: Optional[bytes] = None) -> Any:
        """POST *path*; decode JSON body (same rules as :meth:`get_json`)."""
        raw = self._post(path, query, data).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            preview = raw[:240].strip().replace("\n", " ")
            raise FireliftClientError(
                f"response is not JSON ({e.msg}; body starts: {preview!r})"
            ) from None

    def admin_tsdb_snapshot(self) -> Any:
        """POST ``/api/v1/admin/tsdb/snapshot`` — create an **on-disk** read-only snapshot of current TSDB data.

        Requires Prometheus started with ``--web.enable-admin-api``. Snapshot directory is under the
        server’s data directory (``snapshots/``). This does **not** delete live data; it is **not** the
        same as ``delete_series`` or ``clean_tombstones``.
        """
        return self.post_json("/api/v1/admin/tsdb/snapshot")

    def get_bytes(self, path: str, query: Optional[QueryParam] = None) -> bytes:
        """GET *path* with optional query string parameters (``dict`` or list of pairs, e.g. ``match[]``)."""
        return self._get(path, query)

    def get_text(self, path: str, query: Optional[QueryParam] = None) -> str:
        """GET *path*; decode body as UTF-8 text."""
        return self._get(path, query).decode("utf-8")

    def get_json(self, path: str, query: Optional[QueryParam] = None) -> Any:
        """GET *path*; decode body as JSON.

        Raises:
            FireliftClientError: On HTTP errors or if the body is not valid JSON (e.g. plain-text ``/-/healthy``).
        """
        raw = self._get(path, query).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            preview = raw[:240].strip().replace("\n", " ")
            raise FireliftClientError(
                f"response is not JSON ({e.msg}; body starts: {preview!r})"
            ) from None

    # --- /metrics (Prometheus text format) ---

    def metrics_text(self) -> str:
        """Fetch raw Prometheus exposition format from /metrics."""
        return self.get_text("/metrics")

    @staticmethod
    def parse_metrics_text(text: str) -> list[MetricSample]:
        """Parse Prometheus text; ignores comments and blank lines."""
        out: list[MetricSample] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _METRIC_LINE.match(line)
            if not m:
                continue
            name = m.group("name")
            labels: dict[str, str] = {}
            raw_labels = m.group("labels")
            if raw_labels:
                inner = raw_labels[1:-1]
                for part in _split_label_pairs(inner):
                    k, v = part.split("=", 1)
                    labels[k.strip()] = _unquote_label_value(v.strip())
            value = float(m.group("value"))
            ts = m.group("ts")
            out.append(
                MetricSample(
                    name=name,
                    labels=labels,
                    value=value,
                    timestamp_ms=int(ts) if ts else None,
                )
            )
        return out

    def metrics(self) -> list[MetricSample]:
        """GET /metrics and return parsed samples."""
        return self.parse_metrics_text(self.metrics_text())

    def cluster_slo_samples(self) -> list[MetricSample]:
        """Samples from ``/metrics`` whose names are cluster SLO-related (known prefixes)."""
        prefixes = (
            "cluster_slo_",
            "cluster_remote_slo_",
        )
        return [s for s in self.metrics() if s.name.startswith(prefixes)]

    # --- Prometheus instant query API ---

    def instant_query(self, expr: str) -> dict[str, Any]:
        """Run an instant query; returns the full Prometheus JSON body."""
        raw = self._get("/api/v1/query", {"query": expr})
        return json.loads(raw.decode("utf-8"))

    def instant_query_scalar(self, expr: str) -> float:
        """Return a single scalar-like sample (one series); raises if ambiguous or failed."""
        payload = self.instant_query(expr)
        if payload.get("status") != "success":
            raise FireliftClientError(f"query failed: {payload}")
        result = payload["data"]["result"]
        if not result:
            raise FireliftClientError(f"empty result for query: {expr}")
        if len(result) != 1:
            raise FireliftClientError(
                f"expected scalar-like single result for {expr!r}, got {len(result)} series"
            )
        return float(result[0]["value"][1])

    def iter_slo_query_values(self) -> Iterator[tuple[tuple[str, str], str, float]]:
        """Run each ``SLO_QUERIES`` expression on the query API; yields ``(labels, expr, value)``."""
        for labels, expr in SLO_QUERIES.items():
            yield labels, expr, self.instant_query_scalar(expr)

    # --- Other cluster HTTP helpers (system_exporter, node_ipmi, interface watch list) ---

    def system_probe(self, module: str, target: str) -> str:
        """``system_exporter``: GET /probe — *target* is ``name,mgmt_ip,ctr_ip[:port]``."""
        return self.get_text("/probe", {"module": module, "target": target})

    def system_memory(self) -> Any:
        """``system_exporter``: GET /memory (JSON)."""
        return self.get_json("/memory")

    def ipmi_metrics_text(self, target: str, module: str = "health") -> str:
        """``node_ipmi_exporter``: GET /metrics with *target* and *module* query params."""
        return self.get_text("/metrics", {"target": target, "module": module})

    def interface_watch_list_text(self) -> str:
        """``interface_watch_list_server``: GET /interface_watch_list."""
        return self.get_text("/interface_watch_list")


def _split_label_pairs(inner: str) -> list[str]:
    """Split `a="b",c="d"` on commas that are not inside quotes."""
    parts: list[str] = []
    buf: list[str] = []
    in_string = False
    escape = False
    for ch in inner:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            buf.append(ch)
            continue
        if ch == "," and not in_string:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _unquote_label_value(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        inner = v[1:-1]
        return inner.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")
    return v


def _parse_query_params(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in pairs:
        if "=" not in raw:
            raise SystemExit(f"bad --query {raw!r}, expected KEY=VALUE")
        k, v = raw.split("=", 1)
        out[k] = v
    return out


def _print_samples(samples: list[MetricSample]) -> None:
    for s in samples:
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(s.labels.items()))
        lbl = "{" + label_str + "}" if label_str else ""
        print(f"{s.name}{lbl} {s.value}")


def _stderr_api_status(key: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"API {key} = SUCCESS", file=sys.stderr)
    else:
        line = f"API {key} = ERROR"
        if detail:
            line += f" {detail.replace(chr(10), ' ')[:800]}"
        print(line, file=sys.stderr)


def _endpoint_result(client: FireliftClient, key: str, path: str, query: Optional[QueryParam] = None) -> dict[str, Any]:
    try:
        data = client.get_json(path, query)
        _stderr_api_status(key, True)
        return {"key": key, "status": "ok", "data": data}
    except FireliftClientError as e:
        _stderr_api_status(key, False, str(e))
        return {"key": key, "status": "error", "error": str(e)}


def _endpoint_text(client: FireliftClient, key: str, path: str, query: Optional[QueryParam] = None) -> dict[str, Any]:
    try:
        data = client.get_text(path, query)
        _stderr_api_status(key, True)
        return {"key": key, "status": "ok", "data": data}
    except FireliftClientError as e:
        _stderr_api_status(key, False, str(e))
        return {"key": key, "status": "error", "error": str(e)}


_DIGEST_MAX_METRIC_NAMES = 20_000


def _parse_prometheus_self_metrics_digest(exposition_text: str) -> dict[str, Any]:
    """Derive route hints and metric inventory from Prometheus ``/metrics`` exposition."""
    samples = FireliftClient.parse_metrics_text(exposition_text)
    names = sorted({s.name for s in samples})
    handlers = sorted(
        {
            s.labels["handler"]
            for s in samples
            if s.name == "prometheus_http_requests_total" and "handler" in s.labels
        }
    )
    handler_codes: dict[str, set[str]] = {}
    for s in samples:
        if s.name != "prometheus_http_requests_total":
            continue
        h = s.labels.get("handler")
        c = s.labels.get("code")
        if h and c:
            handler_codes.setdefault(h, set()).add(c)
    hc_json = {h: sorted(cs) for h, cs in sorted(handler_codes.items())}
    truncated = len(names) > _DIGEST_MAX_METRIC_NAMES
    return {
        "parsed_sample_count": len(samples),
        "unique_metric_names_count": len(names),
        "unique_metric_names_truncated": truncated,
        "unique_metric_names": names[:_DIGEST_MAX_METRIC_NAMES] if truncated else names,
        "prometheus_http_requests_handlers": handlers,
        "prometheus_http_requests_handler_codes": hc_json,
    }


# Prometheus registers these for **POST**; we only issue **GET** (no side effects). A 405/404 in
# the JSON still means “this path exists / routing” vs “missing”, useful for exposure review.
_ADMIN_AND_LIFECYCLE_GET_PROBES: tuple[tuple[str, str], ...] = (
    ("admin_get_tsdb_snapshot", "/api/v1/admin/tsdb/snapshot"),
    ("admin_get_tsdb_delete_series", "/api/v1/admin/tsdb/delete_series"),
    ("admin_get_tsdb_clean_tombstones", "/api/v1/admin/tsdb/clean_tombstones"),
    ("lifecycle_get_reload", "/-/reload"),
    ("lifecycle_get_quit", "/-/quit"),
    ("lifecycle_get_healthy", "/-/healthy"),
    ("lifecycle_get_ready", "/-/ready"),
)
_LIFECYCLE_PLAINTEXT_GET: frozenset[str] = frozenset({"lifecycle_get_healthy", "lifecycle_get_ready"})


def prometheus_read_dump(
    client: FireliftClient,
    *,
    include_config: bool = False,
    include_self_metrics: bool = True,
    include_label_values: bool = True,
    include_series_up: bool = True,
    include_admin_probes: bool = True,
) -> dict[str, Any]:
    """Aggregate JSON from Prometheus read-style HTTP APIs plus a parsed ``/metrics`` digest.

    Always fetches ``/metrics`` once to build ``metrics_self_digest`` (handler routes from
    ``prometheus_http_requests_total``, metric name list). Embeds raw exposition only if
    *include_self_metrics* is true. Logs ``API … = SUCCESS|ERROR|SKIPPED`` lines to stderr.
    Unknown or disabled endpoints return ``status: error`` in the list; the dump still completes.

    *Admin/lifecycle paths* are probed with **GET only** (see ``_ADMIN_AND_LIFECYCLE_GET_PROBES``).
    Real admin actions use **POST**; expect **HTTP 405** on GET if the route is mounted — that
    still shows up as ``API … = ERROR`` with “Method Not Allowed” in logs and JSON.
    """
    now = int(time.time())
    results: list[dict[str, Any]] = []

    api_reads: list[tuple[str, str, Optional[QueryParam]]] = [
        ("api_v1_labels", "/api/v1/labels", None),
        ("api_v1_metadata", "/api/v1/metadata", None),
        ("api_v1_rules", "/api/v1/rules", None),
        ("api_v1_alerts", "/api/v1/alerts", None),
        ("api_v1_alertmanagers", "/api/v1/alertmanagers", None),
        ("api_v1_targets_active", "/api/v1/targets", {"state": "active"}),
        ("api_v1_targets_dropped", "/api/v1/targets", {"state": "dropped"}),
        ("api_v1_scrape_pools", "/api/v1/scrape_pools", None),
        ("api_v1_status_buildinfo", "/api/v1/status/buildinfo", None),
        ("api_v1_status_runtimeinfo", "/api/v1/status/runtimeinfo", None),
        ("api_v1_status_tsdb", "/api/v1/status/tsdb", None),
        ("api_v1_status_flags", "/api/v1/status/flags", None),
        ("api_v1_status_walreplay", "/api/v1/status/walreplay", None),
        ("api_v1_notifications", "/api/v1/notifications", None),
        ("api_v1_query_up", "/api/v1/query", {"query": "up"}),
        ("api_v1_format_query", "/api/v1/format_query", {"query": "up"}),
    ]

    for key, path, q in api_reads:
        results.append(_endpoint_result(client, key, path, q))

    if include_admin_probes:
        for key, path in _ADMIN_AND_LIFECYCLE_GET_PROBES:
            if key in _LIFECYCLE_PLAINTEXT_GET:
                entry = _endpoint_text(client, key, path, None)
                if entry.get("status") == "ok" and isinstance(entry.get("data"), str):
                    entry = {**entry, "data": {"plaintext_response": entry["data"]}}
                results.append(entry)
            else:
                results.append(_endpoint_result(client, key, path, None))
    else:
        for key, _path in _ADMIN_AND_LIFECYCLE_GET_PROBES:
            print(f"API {key} = SKIPPED (--no-admin-probes)", file=sys.stderr)

    if include_config:
        results.append(_endpoint_result(client, "api_v1_status_config", "/api/v1/status/config", None))
    else:
        print("API api_v1_status_config = SKIPPED", file=sys.stderr)

    if include_series_up:
        results.append(
            _endpoint_result(
                client,
                "api_v1_series_match_up",
                "/api/v1/series",
                [
                    ("match[]", "up"),
                    ("start", str(now - 3600)),
                    ("end", str(now)),
                ],
            )
        )
    else:
        print("API api_v1_series_match_up = SKIPPED", file=sys.stderr)

    label_values: dict[str, Any] = {}
    labels_res = next((r for r in results if r.get("key") == "api_v1_labels"), None)
    if (
        include_label_values
        and labels_res
        and labels_res.get("status") == "ok"
        and isinstance(labels_res.get("data"), dict)
        and labels_res["data"].get("status") == "success"
    ):
        raw_label_names = labels_res["data"].get("data") or []
        if isinstance(raw_label_names, list):
            for name in sorted(raw_label_names):
                if not isinstance(name, str):
                    continue
                enc = urllib.parse.quote(name, safe="")
                label_values[name] = _endpoint_result(
                    client, f"api_v1_label_values/{name}", f"/api/v1/label/{enc}/values", None
                )
    if include_label_values:
        _stderr_api_status("api_v1_label_values_all", True)
    else:
        print("API api_v1_label_values_all = SKIPPED", file=sys.stderr)
    results.append(
        {
            "key": "api_v1_label_values_all",
            "status": "ok" if include_label_values else "skipped",
            "data": label_values if include_label_values else None,
        }
    )

    metrics_text: Optional[str] = None
    try:
        metrics_text = client.metrics_text()
        _stderr_api_status("metrics_self_fetch", True)
    except FireliftClientError as e:
        _stderr_api_status("metrics_self_fetch", False, str(e))
        results.append({"key": "metrics_self_digest", "status": "error", "error": str(e)})
    else:
        digest = _parse_prometheus_self_metrics_digest(metrics_text)
        results.append({"key": "metrics_self_digest", "status": "ok", "data": digest})

    if include_self_metrics and metrics_text is not None:
        results.append({"key": "metrics_self", "status": "ok", "data": metrics_text})
        _stderr_api_status("metrics_self (full body in JSON)", True)
    elif include_self_metrics and metrics_text is None:
        print("API metrics_self (full body in JSON) = SKIPPED (fetch failed)", file=sys.stderr)
    else:
        print("API metrics_self (full body in JSON) = SKIPPED (--no-self-metrics)", file=sys.stderr)

    return {
        "_meta": {
            "base_url": client.base_url,
            "unix_time": now,
            "note": "Per-endpoint objects use status ok|error. Progress lines go to stderr. "
            "metrics_self_digest derives HTTP handler hints from prometheus_http_requests_total. "
            f"unique_metric_names may be truncated beyond {_DIGEST_MAX_METRIC_NAMES} names. "
            "Admin TSDB and /-/ lifecycle routes are GET-probed only; 405 means POST-only route exists.",
        },
        "endpoints": results,
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Firelift: Prometheus /metrics and /api/v1/query client, plus cluster exporter helpers.",
    )
    p.add_argument("--url", default="http://127.0.0.1:9090", help="Base URL (no trailing slash)")
    p.add_argument("--timeout", type=float, default=30.0, help="Per-request timeout in seconds")
    p.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify TLS certificates (default: skip verification for HTTPS, e.g. self-signed)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("metrics", help="GET /metrics (raw Prometheus text from any exporter)")
    m.add_argument(
        "--parse",
        action="store_true",
        help="Parse exposition text and print one metric per line (name{labels} value)",
    )
    m.add_argument("--prefix", help="With --parse: only metrics whose name starts with this string")

    sub.add_parser(
        "slo-text",
        help="GET /metrics and print samples matching cluster_slo_* / cluster_remote_slo_* name prefixes",
    )

    q = sub.add_parser(
        "query",
        help="GET /api/v1/query?query=... (Prometheus or Thanos instant query API)",
    )
    q.add_argument("expr", help="PromQL expression")
    q.add_argument(
        "--scalar",
        action="store_true",
        help="Print a single float (fails if the result is not exactly one series)",
    )

    sub.add_parser(
        "slo-queries",
        help="Run every mirrored SLO expression via instant query API (requires PromQL base URL)",
    )

    pr = sub.add_parser("probe", help="system_exporter: GET /probe?module=&target=")
    pr.add_argument("--module", default="ssh", help="Probe module (default: ssh)")
    pr.add_argument(
        "--target",
        required=True,
        help="Comma-separated: system_name,mgmt_ip,controller_ip[:port] (port stripped server-side)",
    )

    sub.add_parser("memory", help="system_exporter: GET /memory (JSON)")
    sub.add_parser("iwl", help="interface_watch_list_server: GET /interface_watch_list")

    ip = sub.add_parser("ipmi-metrics", help="node_ipmi_exporter: GET /metrics?target=&module=")
    ip.add_argument("--target", required=True, help="BMC / IPMI hostname")
    ip.add_argument("--module", default="health", help="Redfish module key (default: health)")

    r = sub.add_parser("raw", help="GET an arbitrary path (optional query parameters)")
    r.add_argument("path", help="URL path, e.g. /metrics or metrics")
    r.add_argument(
        "-q",
        "--query",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Repeat for each query parameter",
    )

    d = sub.add_parser(
        "dump-prometheus",
        help="Single shot: GET common Prometheus read APIs + optional /metrics; JSON to stdout or --output",
    )
    d.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="Write JSON to this file (compact by default). Stdout only used if omitted.",
    )
    d.add_argument(
        "--pretty",
        action="store_true",
        help="With --output: indented JSON (larger on disk)",
    )
    d.add_argument(
        "--include-config",
        action="store_true",
        help="Also GET /api/v1/status/config (large; may 403)",
    )
    d.add_argument(
        "--no-self-metrics",
        action="store_true",
        help="Omit raw /metrics body from output (can be huge)",
    )
    d.add_argument(
        "--no-label-values",
        action="store_true",
        help="Skip /api/v1/label/<name>/values for every label name",
    )
    d.add_argument(
        "--no-series",
        action="store_true",
        help="Skip /api/v1/series?match[]=up (1h window)",
    )
    d.add_argument(
        "--no-admin-probes",
        action="store_true",
        help="Skip GET probes of /api/v1/admin/tsdb/* and /-/reload|quit|healthy|ready (POST-only routes often return 405)",
    )

    sub.add_parser(
        "tsdb-snapshot",
        help="POST /api/v1/admin/tsdb/snapshot (on-disk backup slice; requires --web.enable-admin-api on server)",
    )

    return p


def main(argv: Optional[list[str]] = None) -> None:
    args = _build_arg_parser().parse_args(argv)
    client = FireliftClient(
        base_url=args.url,
        timeout_seconds=args.timeout,
        verify_ssl=args.verify_ssl,
    )

    try:
        if args.command == "tsdb-snapshot":
            print(json.dumps(client.admin_tsdb_snapshot(), indent=2))
            return

        if args.command == "dump-prometheus":
            doc = prometheus_read_dump(
                client,
                include_config=args.include_config,
                include_self_metrics=not args.no_self_metrics,
                include_label_values=not args.no_label_values,
                include_series_up=not args.no_series,
                include_admin_probes=not args.no_admin_probes,
            )
            out_path = getattr(args, "output", None)
            if out_path:
                with open(out_path, "w", encoding="utf-8") as fh:
                    if args.pretty:
                        json.dump(doc, fh, ensure_ascii=False, indent=2)
                    else:
                        json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"))
                print(f"Wrote {out_path}", file=sys.stderr)
            else:
                print(json.dumps(doc, indent=2))
            return

        if args.command == "metrics":
            text = client.metrics_text()
            if args.parse:
                samples = FireliftClient.parse_metrics_text(text)
                if args.prefix:
                    samples = [s for s in samples if s.name.startswith(args.prefix)]
                _print_samples(samples)
            else:
                sys.stdout.write(text)

        elif args.command == "slo-text":
            _print_samples(client.cluster_slo_samples())

        elif args.command == "query":
            if args.scalar:
                print(client.instant_query_scalar(args.expr))
            else:
                print(json.dumps(client.instant_query(args.expr), indent=2))

        elif args.command == "slo-queries":
            for (metric_name, window), expr, value in client.iter_slo_query_values():
                print(f"{metric_name}\t{window}\t{value}\t{expr}")

        elif args.command == "probe":
            sys.stdout.write(client.system_probe(args.module, args.target))

        elif args.command == "memory":
            print(json.dumps(client.system_memory(), indent=2))

        elif args.command == "iwl":
            sys.stdout.write(client.interface_watch_list_text())

        elif args.command == "ipmi-metrics":
            sys.stdout.write(client.ipmi_metrics_text(args.target, args.module))

        elif args.command == "raw":
            q = _parse_query_params(args.query)
            sys.stdout.write(client.get_text(args.path, q or None))

    except FireliftClientError as e:
        print(f"{args.command}: {e}", file=sys.stderr)
        raise SystemExit(1) from e
