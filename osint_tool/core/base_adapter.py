"""
core/base_adapter.py
Abstract base class for every data-source adapter.
All adapters MUST inherit from BaseAdapter and implement `fetch()`.
"""

import time
import logging
import random
import urllib.robotparser
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import requests
from fake_useragent import UserAgent
from tenacity import retry, stop_after_attempt, wait_exponential

from config import settings

logger = logging.getLogger(__name__)


class AdapterResult:
    """
    Standardised data container returned by every adapter.
    Every data point carries a source URL + retrieval timestamp (audit trail).
    """

    def __init__(
        self,
        adapter_name: str,
        category: str,
        data: List[Dict[str, Any]],
        errors: Optional[List[str]] = None,
    ):
        self.adapter_name  = adapter_name
        self.category      = category           # e.g. "social", "infrastructure", "regulatory"
        self.data          = data               # list of finding dicts
        self.errors        = errors or []
        self.retrieved_at  = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {
            "adapter":       self.adapter_name,
            "category":      self.category,
            "retrieved_at":  self.retrieved_at,
            "record_count":  len(self.data),
            "data":          self.data,
            "errors":        self.errors,
        }


class BaseAdapter(ABC):
    """
    Abstract base for all OSINT adapters.

    Subclasses must implement:
        fetch(entity: str, entity_type: str) -> AdapterResult
    """

    CATEGORY: str = "generic"          # override in each subclass
    ADAPTER_NAME: str = "base"         # override in each subclass

    def __init__(self):
        self._ua      = UserAgent()
        self._session = self._build_session()
        self._rp_cache: Dict[str, urllib.robotparser.RobotFileParser] = {}
        self._last_request_time: float = 0.0
        self._request_count: int = 0
        self._proxy_rotate_time: float = 0.0

    # ── Session & OPSEC helpers ───────────────────────────────────────────────

    def _build_session(self) -> requests.Session:
        import requests_cache
        from pathlib import Path
        cache_name = str(Path(settings.BASE_DIR) / "osint_cache")
        session = requests_cache.CachedSession(
            cache_name=cache_name,
            expire_after=86400,  # 24 hours
            allowable_methods=('GET', 'POST'),
        )
        session.headers.update({"User-Agent": self._ua.random})
        if settings.USE_PROXIES and settings.PROXY_LIST:
            proxy = random.choice(settings.PROXY_LIST)
            session.proxies = {"http": proxy, "https": proxy}
            logger.debug("Using proxy: %s", proxy)
        return session

    def _rotate_user_agent(self):
        """Rotate user-agent on every request for stealth."""
        self._session.headers["User-Agent"] = self._ua.random

    def _rotate_proxy(self):
        """Rotate proxy based on PROXY_ROTATION_INTERVAL."""
        if not settings.USE_PROXIES or not settings.PROXY_LIST:
            return
        
        current_time = time.time()
        if current_time - self._proxy_rotate_time >= settings.PROXY_ROTATION_INTERVAL:
            new_proxy = random.choice(settings.PROXY_LIST)
            self._session.proxies = {"http": new_proxy, "https": new_proxy}
            logger.debug("Rotated proxy: %s", new_proxy)
            self._proxy_rotate_time = current_time

    def _respect_robots(self, url: str) -> bool:
        """
        Returns True if we are allowed to fetch this URL per robots.txt.
        Caches the parsed robots.txt per domain.
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._rp_cache:
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(f"{base}/robots.txt")
            try:
                rp.read()
            except Exception:
                # If we can't read robots.txt, be conservative and allow
                rp = None
            self._rp_cache[base] = rp
        rp = self._rp_cache[base]
        if rp is None:
            return True
        return rp.can_fetch("*", url)

    @retry(
        stop=stop_after_attempt(settings.MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    def _get(self, url: str, **kwargs) -> requests.Response:
        """
        Rate-limited, retry-enabled GET with:
        - robots.txt compliance
        - Per-adapter rate limiting
        - Proxy rotation
        - User-agent randomization
        """
        # Check robots.txt
        if not self._respect_robots(url):
            raise PermissionError(f"robots.txt disallows: {url}")
        
        # Rotate user agent and proxy
        self._rotate_user_agent()
        self._rotate_proxy()
        
        # Apply rate limiting (use adapter-specific or default)
        adapter_rate = settings.ADAPTER_RATE_LIMITS.get(self.ADAPTER_NAME, settings.DEFAULT_RATE_LIMIT)
        elapsed = time.time() - self._last_request_time
        if elapsed < adapter_rate:
            delay = adapter_rate - elapsed + random.uniform(0, 0.5)
            logger.debug(f"Rate limiting: sleeping {delay:.1f}s")
            time.sleep(delay)
        
        self._last_request_time = time.time()
        self._request_count += 1
        
        logger.debug(f"[{self.ADAPTER_NAME}] Request #{self._request_count}: {url[:80]}")
        
        resp = self._session.get(url, timeout=settings.DEFAULT_TIMEOUT, **kwargs)
        resp.raise_for_status()
        return resp

    # ── Helpers for building standardised finding dicts ───────────────────────

    @staticmethod
    def make_finding(
        title: str,
        value: Any,
        source_url: str,
        risk_tags: Optional[List[str]] = None,
        metadata: Optional[Dict] = None,
    ) -> Dict:
        return {
            "title":        title,
            "value":        value,
            "source_url":   source_url,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "risk_tags":    risk_tags or [],
            "metadata":     metadata or {},
        }

    # ── Interface ─────────────────────────────────────────────────────────────

    @abstractmethod
    def fetch(self, entity: str, entity_type: str) -> AdapterResult:
        """
        Main entry point for each adapter.

        Args:
            entity:      The target name (company or individual).
            entity_type: "company" | "individual"

        Returns:
            AdapterResult with all findings + audit metadata.
        """
        ...
