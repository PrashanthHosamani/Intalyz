"""
analysis/entity_resolver.py
Phase II — Entity Resolution.
Groups, deduplicates, and validates findings across all adapters.
Uses fuzzy matching + NLP NER to link assets to the parent entity.
"""

import logging
import re
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

from rapidfuzz import fuzz

logger = logging.getLogger(__name__)

# Confidence threshold — findings below this are flagged as potential false positives
# STRICT FILTERING: 70% threshold to eliminate keyword-based noise and include only verified information
CONFIDENCE_THRESHOLD = 70


class EntityResolver:
    """
    Given raw aggregated findings, this resolver:
     1. Groups findings by asset type (domain, IP, email, person, company)
     2. Links each asset back to the parent entity with a confidence score
     3. Flags likely false positives
     4. Deduplicates identical source URLs
    """

    def __init__(self, entity: str, entity_type: str, aliases: list = None):
        self.entity      = entity
        self.entity_type = entity_type
        self.aliases     = aliases or []   # e.g. related company names
        self._seen_urls: set = set()

    def resolve(self, raw_results: List[Dict]) -> Dict[str, Any]:
        """
        Process all adapter results into a clean, grouped structure.

        Returns:
            {
                "entity":           str,
                "grouped_assets":   { category: [finding, ...] },
                "false_positives":  [finding, ...],
                "confirmed":        [finding, ...],
                "dedup_count":      int,
            }
        """
        all_findings: List[Dict] = []
        dedup_count = 0

        # Flatten all findings from all adapter results
        for adapter_result in raw_results:
            for finding in adapter_result.get("data", []):
                url = finding.get("source_url", "")
                if url and url in self._seen_urls:
                    dedup_count += 1
                    continue
                if url:
                    self._seen_urls.add(url)
                all_findings.append({
                    **finding,
                    "adapter":  adapter_result.get("adapter"),
                    "category": adapter_result.get("category"),
                })

        # Score each finding for relevance to the entity
        confirmed       = []
        false_positives = []

        for finding in all_findings:
            score = self._confidence_score(finding)
            finding["confidence_score"] = score
            if score >= CONFIDENCE_THRESHOLD:
                confirmed.append(finding)
            else:
                false_positives.append(finding)

        # Group confirmed findings by category
        grouped: Dict[str, List] = {}
        for finding in confirmed:
            cat = finding.get("category", "misc")
            grouped.setdefault(cat, []).append(finding)

        logger.info(
            "Entity resolution: %d confirmed, %d false positives, %d duplicates removed",
            len(confirmed), len(false_positives), dedup_count
        )

        return {
            "entity":          self.entity,
            "entity_type":     self.entity_type,
            "grouped_assets":  grouped,
            "false_positives": false_positives,
            "confirmed":       confirmed,
            "dedup_count":     dedup_count,
            "total_findings":  len(all_findings) + dedup_count,
        }

    # ── Confidence scoring ────────────────────────────────────────────────────

    def _confidence_score(self, finding: Dict) -> float:
        """
        Score 0-100: how likely is this finding to be about our target entity?
        Combines fuzzy string matching on multiple text fields.
        """
        scores = []
        entity_lower = self.entity.lower()

        # Extract text fields to match against
        text_targets = self._extract_text_fields(finding)
        # All names to match against: primary entity + any aliases
        name_targets = [entity_lower] + [a.lower() for a in self.aliases]

        for text in text_targets:
            if not text:
                continue
            text_lower = str(text).lower()

            for name in name_targets:
                # Exact substring match → high confidence
                if name in text_lower:
                    scores.append(95)
                    break

                # Fuzzy token sort ratio (handles word-order differences)
                ratio = fuzz.token_sort_ratio(name, text_lower)
                scores.append(ratio)

                # Also check domain similarity
                domain_score = self._domain_similarity(name, text_lower)
                if domain_score > 0:
                    scores.append(domain_score)

        if not scores:
            return 50  # Neutral if no text to compare

        return max(scores)

    def _extract_text_fields(self, finding: Dict) -> List[str]:
        """Pull all text values recursively from a finding dict."""
        texts = []
        value = finding.get("value", {})

        if isinstance(value, dict):
            for v in value.values():
                if isinstance(v, str):
                    texts.append(v)
                elif isinstance(v, list):
                    texts.extend([str(i) for i in v if i])
        elif isinstance(value, str):
            texts.append(value)

        # Also check title and source URL
        texts.append(finding.get("title", ""))
        texts.append(finding.get("source_url", ""))

        return texts

    @staticmethod
    def _domain_similarity(entity: str, text: str) -> float:
        """Check if entity name appears in a domain/URL."""
        slug = re.sub(r"[^a-z0-9]", "", entity)  # strip non-alphanumeric
        if not slug:
            return 0
        # Extract domain from URL if present
        try:
            parsed = urlparse(text if text.startswith("http") else f"http://{text}")
            domain = parsed.netloc or parsed.path
            domain_slug = re.sub(r"[^a-z0-9]", "", domain)
            if slug in domain_slug:
                return 90
        except Exception:
            pass
        return 0
