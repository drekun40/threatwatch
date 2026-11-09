"""Shared HTTP helpers for collectors: a few quick retries for transient failures.

Retried: connection errors, timeouts, and HTTP 500/502/503/504 — up to `tries` attempts with a short
backoff (0.8 s, then 1.6 s). Not retried: 4xx answers, including 429 (rate limits are handled by
the collector that knows the service, e.g. GDELT backs off for 45 minutes). The final response is
returned as-is, so callers still call raise_for_status() and a failure still raises; one failing
source never stops a scan because the pipeline catches it per source.
"""
from __future__ import annotations

import time

import requests

RETRY_STATUS = {500, 502, 503, 504}
DEFAULT_TRIES = 3
BACKOFF_S = 0.8


def request(method: str, url: str, *, session: requests.Session | None = None, tries: int = DEFAULT_TRIES,
            backoff: float = BACKOFF_S, **kw) -> requests.Response:
    kw.setdefault("timeout", 20)
    caller = session if session is not None else requests
    last_exc: Exception | None = None
    for attempt in range(max(1, tries)):
        if attempt:
            time.sleep(backoff * (2 ** (attempt - 1)))
        try:
            r = getattr(caller, method)(url, **kw)
        except (requests.ConnectionError, requests.Timeout) as e:
            last_exc = e
            continue
        if getattr(r, "status_code", 200) in RETRY_STATUS and attempt < tries - 1:
            continue
        return r
    assert last_exc is not None
    raise last_exc


def get(url: str, **kw) -> requests.Response:
    return request("get", url, **kw)


def post(url: str, **kw) -> requests.Response:
    return request("post", url, **kw)
