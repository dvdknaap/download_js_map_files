"""HTTP session construction."""

from __future__ import annotations

from collections.abc import Mapping

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def create_session(headers: Mapping[str, str], proxy: str | None, retries: int) -> requests.Session:
    """Create a configured requests session for recon traffic."""

    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(headers)
    session.verify = False

    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    return session
