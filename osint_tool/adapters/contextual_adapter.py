"""
adapters/contextual_adapter.py
Contextual & Regulatory — breach status (XposedOrNot), corporate registry
(Wikipedia), and news archive (NewsAPI).
Includes rate limiting and robots.txt checks.
"""

import logging
import time
from typing import List, Dict, Any

from core.base_adapter import BaseAdapter, AdapterResult
from config import settings

logger = logging.getLogger(__name__)


class ContextualAdapter(BaseAdapter):
    """
    Combines three regulatory / contextual data sources in one adapter:
      1. XposedOrNot               — breach detection (emails)
      2. Wikipedia API             — entity background and overview
      3. NewsAPI                   — recent news mentions
    
    Applies rate limiting between API calls.
    """

    CATEGORY     = "regulatory"
    ADAPTER_NAME = "contextual"

    def fetch(self, entity: str, entity_type: str) -> AdapterResult:
        import concurrent.futures
        findings: List[Dict[str, Any]] = []
        errors:   List[str]            = []

        # Get adapter-specific rate limit
        adapter_rate = settings.ADAPTER_RATE_LIMITS.get(self.ADAPTER_NAME, settings.DEFAULT_RATE_LIMIT)

        def run_xposed():
            return self._check_xposedornot(entity, entity_type, adapter_rate, errors)

        def run_wiki():
            return self._check_wikipedia(entity, adapter_rate, errors)

        def run_news():
            return self._check_news(entity, adapter_rate, errors)

        # Run the API fetches concurrently since they target different services
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            f_xposed = executor.submit(run_xposed)
            f_wiki   = executor.submit(run_wiki)
            f_news   = executor.submit(run_news)

            findings.extend(f_xposed.result())
            findings.extend(f_wiki.result())
            findings.extend(f_news.result())

        logger.info("✓ %s found %d records", self.ADAPTER_NAME, len(findings))
        return AdapterResult(self.ADAPTER_NAME, self.CATEGORY, findings, errors)

    # ── Rate Limiting Helper ──────────────────────────────────────────────────
    
    def _apply_rate_limit(self, adapter_rate: float):
        """Apply rate limiting before next API call."""
        elapsed = time.time() - self._last_request_time
        if elapsed < adapter_rate:
            delay = adapter_rate - elapsed
            logger.debug("Rate limiting: sleeping %.1fs", delay)
            time.sleep(delay)
        self._last_request_time = time.time()
        self._request_count += 1

    # ── XposedOrNot ───────────────────────────────────────────────────────────

    def _check_xposedornot(self, entity: str, entity_type: str, adapter_rate: float, errors: list) -> list:
        findings = []
        search_targets = self._generate_xposed_targets(entity, entity_type)
        
        for target in search_targets:
            self._apply_rate_limit(adapter_rate)
            try:
                url = f"https://api.xposedornot.com/v1/check-email/{target}"
                logger.debug("XposedOrNot lookup: %s", target)
                
                resp = self._session.get(url, timeout=settings.DEFAULT_TIMEOUT)
                
                if resp.status_code == 200:
                    data = resp.json()
                    breaches = data.get("breaches", [[]])[0]
                    if breaches:
                        findings.append(
                            self.make_finding(
                                title="Data Breach Found (XposedOrNot)",
                                value={
                                    "target": target,
                                    "breaches": breaches,
                                    "count": len(breaches)
                                },
                                source_url=f"https://xposedornot.com/?email={target}",
                                risk_tags=["breach"],
                            )
                        )
                elif resp.status_code == 404:
                    logger.debug("XposedOrNot: No breaches found for %s", target)
                    
            except Exception as exc:
                msg = f"XposedOrNot error [{target}]: {exc}"
                logger.warning(msg)
                errors.append(msg)

        return findings

    @staticmethod
    def _generate_xposed_targets(entity: str, entity_type: str) -> List[str]:
        targets = []
        if entity_type == "individual":
            parts = entity.lower().split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                targets.extend([
                    f"{first}.{last}@gmail.com",
                    f"{first}{last}@gmail.com",
                    f"{first}@yahoo.com",
                    f"{first}.{last}@outlook.com",
                ])
            else:
                targets.append(f"{entity.lower()}@gmail.com")
        else:
            slug = entity.lower().replace(" ", "")
            targets.append(f"contact@{slug}.com")
            targets.append(f"info@{slug}.com")
            targets.append(f"admin@{slug}.com")
        return targets

    # ── Wikipedia ─────────────────────────────────────────────────────────────

    def _check_wikipedia(self, entity: str, adapter_rate: float, errors: list) -> list:
        findings = []
        base_url = "https://en.wikipedia.org/w/api.php"
        params = {
            "action": "query",
            "list": "search",
            "srsearch": entity,
            "utf8": "",
            "format": "json"
        }

        try:
            logger.debug("Wikipedia search: %s", entity)
            resp = self._session.get(base_url, params=params, timeout=settings.DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("query", {}).get("search", [])
                
                if results:
                    best_match = results[0]
                    import re
                    snippet = re.sub('<[^<]+>', '', best_match.get("snippet", ""))
                    
                    findings.append(
                        self.make_finding(
                            title="Wikipedia Overview",
                            value={
                                "title": best_match.get("title"),
                                "snippet": snippet + "...",
                                "word_count": best_match.get("wordcount")
                            },
                            source_url=f"https://en.wikipedia.org/wiki/{best_match.get('title').replace(' ', '_')}",
                            risk_tags=self._news_risk_tags(snippet),
                        )
                    )
        except Exception as exc:
            msg = f"Wikipedia error: {exc}"
            logger.warning(msg)
            errors.append(msg)

        return findings

    # ── NewsAPI ───────────────────────────────────────────────────────────────

    def _check_news(self, entity: str, adapter_rate: float, errors: list) -> list:
        findings = []
        if not settings.NEWS_API_KEY:
            errors.append("NEWS_API_KEY not set — skipping news check")
            return findings

        url    = "https://newsapi.org/v2/everything"
        params = {
            "q":        f'"{entity}"',
            "sortBy":   "relevancy",
            "pageSize": settings.CONTEXTUAL_MAX_NEWS_ARTICLES,
            "apiKey":   settings.NEWS_API_KEY,
        }

        try:
            logger.debug("NewsAPI search: %s", entity)
            resp = self._session.get(url, params=params, timeout=settings.DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                articles = resp.json().get("articles", [])
                for article in articles:
                    article_url = article.get("url", "")
                    
                    if article_url and not self._respect_robots(article_url):
                        logger.debug("robots.txt disallows: %s", article_url)
                        continue
                    
                    risk_tags = self._news_risk_tags(
                        (article.get("title", "") or "") + " " + (article.get("description", "") or "")
                    )
                    findings.append(
                        self.make_finding(
                            title="News Mention",
                            value={
                                "headline":    article.get("title"),
                                "source":      article.get("source", {}).get("name"),
                                "published":   article.get("publishedAt"),
                                "description": str(article.get("description", ""))[:300],
                                "url":         article_url,
                                "author":      article.get("author"),
                            },
                            source_url=article_url or url,
                            risk_tags=risk_tags,
                        )
                    )
        except Exception as exc:
            msg = f"NewsAPI error: {exc}"
            logger.warning(msg)
            errors.append(msg)

        return findings

    # ── Risk Tagging Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _corp_risk_tags(co: dict) -> list:
        tags = []
        if co.get("dissolution_date"):
            tags.append("news_negative")
        return tags

    @staticmethod
    def _news_risk_tags(text: str) -> list:
        tags = []
        negative_keywords = [
            "lawsuit", "fraud", "scandal", "breach", "hack", "leak",
            "investigation", "fine", "penalty", "bankruptcy", "arrested",
        ]
        lowered = text.lower()
        for kw in negative_keywords:
            if kw in lowered:
                tags.append("news_negative")
                break
        return tags
