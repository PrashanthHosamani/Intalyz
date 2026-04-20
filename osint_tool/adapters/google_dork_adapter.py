"""
adapters/google_dork_adapter.py
Social & Public Footprint — Automated Google Dorking.
Searches for publicly indexed mentions of the target entity.
Respects rate limiting and robots.txt.
"""

import logging
import time
from typing import List
from urllib.parse import quote_plus

from core.base_adapter import BaseAdapter, AdapterResult
from config import settings

logger = logging.getLogger(__name__)


# Dork templates — {entity} is substituted at runtime
DORK_TEMPLATES = {
    "company": [
        '"{entity}" site:linkedin.com',
        '"{entity}" filetype:pdf',
        '"{entity}" "annual report"',
        '"{entity}" "data breach" OR "leaked"',
        '"{entity}" inurl:github.com',
        '"{entity}" "phone" OR "address" OR "email" site:yellowpages.com OR site:yelp.com',
        '"{entity}" site:crunchbase.com',
        '"{entity}" "board of directors" OR "CEO" OR "founder"',
    ],
    "individual": [
        '"{entity}" site:linkedin.com',
        '"{entity}" site:twitter.com OR site:x.com',
        '"{entity}" "email" OR "@gmail" OR "@yahoo"',
        '"{entity}" "resume" OR "CV" filetype:pdf',
        '"{entity}" site:github.com',
        '"{entity}" "phone number" OR "address"',
        '"{entity}" "interview" OR "keynote" OR "speaker"',
    ],
}


class GoogleDorkAdapter(BaseAdapter):
    """
    Uses the googlesearch-python library to run structured dork queries.
    Respects robots.txt and applies per-query rate limiting.
    """

    CATEGORY     = "social"
    ADAPTER_NAME = "google_dork"

    def fetch(self, entity: str, entity_type: str) -> AdapterResult:
        findings = []
        errors   = []
        templates = DORK_TEMPLATES.get(entity_type, DORK_TEMPLATES["company"])

        try:
            from googlesearch import search as gsearch
        except ImportError:
            return AdapterResult(
                self.ADAPTER_NAME, self.CATEGORY, [],
                errors=["googlesearch-python not installed"]
            )

        # Get adapter-specific rate limit
        adapter_rate = settings.ADAPTER_RATE_LIMITS.get(self.ADAPTER_NAME, settings.DEFAULT_RATE_LIMIT)
        max_results = settings.GOOGLE_DORK_MAX_RESULTS_PER_QUERY
        
        for template in templates:
            query = template.format(entity=entity)
            try:
                logger.info("Google Dork query: %s", query)
                
                # Apply rate limiting before each query
                elapsed = time.time() - self._last_request_time
                if elapsed < adapter_rate:
                    delay = adapter_rate - elapsed
                    logger.debug("Rate limiting: sleeping %.1fs before query", delay)
                    time.sleep(delay)
                
                self._last_request_time = time.time()
                self._request_count += 1
                
                # Aggressive delay to completely avoid Google 429 rate limiting
                # Google blocks requests when they detect automated queries
                urls: List[str] = list(gsearch(query, num_results=max_results, sleep_interval=8.0))
                
                for url in urls:
                    # Check robots.txt before including
                    if not self._respect_robots(url):
                        logger.debug("robots.txt disallows: %s", url)
                        continue
                    
                    findings.append(
                        self.make_finding(
                            title="Google Dork Result",
                            value={"query": query, "url": url},
                            source_url=url,
                            risk_tags=self._tag_url(url),
                        )
                    )
                
                logger.info("  ✓ Found %d results from dork", len(urls))
                
            except Exception as exc:
                msg = f"Dork failed [{query}]: {exc}"
                logger.warning(msg)
                errors.append(msg)

        return AdapterResult(self.ADAPTER_NAME, self.CATEGORY, findings, errors)

    @staticmethod
    def _tag_url(url: str) -> list:
        """Assign risk tags based on URL patterns."""
        tags = []
        lowered = url.lower()
        if "breach" in lowered or "leak" in lowered:
            tags.append("breach")
        if "github" in lowered:
            tags.append("public_repo")
        if "pastebin" in lowered or "paste" in lowered:
            tags.append("leaked_secret")
        return tags
