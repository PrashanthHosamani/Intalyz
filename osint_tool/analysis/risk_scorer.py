"""
analysis/risk_scorer.py
Professional OSINT Risk Scoring Engine.

Methodology: Multi-dimensional risk assessment based on industry-standard
corporate due diligence frameworks.

Risk Score = weighted combination of 5 risk dimensions:
  1. CYBER EXPOSURE    (30%) — breaches, leaked secrets, exposed ports
  2. REPUTATION        (25%) — negative news, scam mentions, bad reviews
  3. DIGITAL PRESENCE  (15%) — public repos, DNS anomalies, WHOIS privacy
  4. FINANCIAL HEALTH  (15%) — negative profits, high debt
  5. VERIFICATION GAP  (15%) — how many verification checks failed

Each dimension scores 0-100, then they're combined with weights.
A company with NO risk tags and ALL verifications passed gets score ~5 (MINIMAL).
"""

import logging
from typing import List, Dict, Any

from config.settings import RISK_WEIGHTS

logger = logging.getLogger(__name__)

# Severity bands
SEVERITY_BANDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0,  "MINIMAL"),
]

# Map each risk_tag to a dimension
TAG_DIMENSIONS = {
    "breach":           "cyber",
    "exposed_port":     "cyber",
    "leaked_secret":    "cyber",
    "dark_web_mention": "cyber",
    "news_negative":    "reputation",
    "public_repo":      "digital",
    "whois_privacy":    "digital",
    "dns_anomaly":      "digital",
    "negative_profit":  "financial",
    "high_debt":        "financial",
}

# Dimension weights (must sum to 1.0)
DIMENSION_WEIGHTS = {
    "cyber":        0.30,
    "reputation":   0.25,
    "digital":      0.15,
    "financial":    0.15,
    "verification": 0.15,
}

# Max reasonable raw score per dimension before normalization
DIMENSION_CAPS = {
    "cyber":        40,   # e.g. 4 breaches × 10 weight = 40
    "reputation":   25,   # e.g. 5 negative news × 5 weight = 25
    "digital":      15,   # e.g. 5 public repos × 3 weight = 15
    "financial":    12,   # e.g. both negative_profit + high_debt = 11
    "verification": 100,  # calculated from % of failed checks
}


class RiskScorer:
    """
    Professional multi-dimensional risk scorer.

    Instead of naively summing all tags, this evaluates 5 separate risk
    dimensions, normalizes each to 0-100, then produces a weighted composite.

    This prevents a company with many harmless findings (public repos, DNS
    records) from getting a CRITICAL score — only actual threats drive
    the score up.
    """

    def score(self, resolved: Dict[str, Any]) -> Dict[str, Any]:
        confirmed: List[Dict] = resolved.get("confirmed", [])

        # ── Step 1: Categorize risk tags into dimensions ──
        dimension_raw: Dict[str, float] = {
            "cyber": 0, "reputation": 0, "digital": 0, "financial": 0,
        }

        tag_counts: Dict[str, int] = {}
        for finding in confirmed:
            for tag in finding.get("risk_tags", []):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        breakdown: Dict[str, Dict] = {}
        for tag, count in tag_counts.items():
            weight = RISK_WEIGHTS.get(tag, 1)
            subtotal = weight * count
            dimension = TAG_DIMENSIONS.get(tag, "digital")
            dimension_raw[dimension] = dimension_raw.get(dimension, 0) + subtotal
            breakdown[tag] = {
                "count": count,
                "weight": weight,
                "subtotal": subtotal,
                "dimension": dimension,
            }

        # ── Step 2: Calculate verification gap score ──
        # ONLY count actual negative signals, NOT "not found on platform X"
        # "Not found on SEC" just means company isn't US-listed — that's normal.
        # We only flag risk if a company has NO online presence at all, or
        # if pages were found but entity name didn't match (possible fake).
        verification_results = [
            f for f in confirmed if f.get("title") == "Verification Result"
        ]
        verification_score = 0  # Default: no penalty
        if verification_results:
            # Count how many were actually VERIFIED (confirmed match)
            verified_count = sum(
                1 for f in verification_results
                if "VERIFIED" in str(f.get("value", {}).get("status", ""))
                or "FOUND" in str(f.get("value", {}).get("status", ""))
            )
            total_checks = len(verification_results)

            # Only penalize if NOTHING was verified at all (complete ghost company)
            if verified_count == 0 and total_checks > 0:
                verification_score = 80  # Very suspicious — no presence anywhere
            elif verified_count <= 1 and total_checks > 5:
                verification_score = 40  # Weak presence — only 1 verification out of many
            else:
                verification_score = 0   # Has presence — no penalty

        dimension_raw["verification"] = verification_score

        # ── Step 3: Normalize each dimension to 0-100 ──
        dimension_scores: Dict[str, float] = {}
        active_dimensions: Dict[str, float] = {}  # Only dimensions with actual data

        for dim, raw in dimension_raw.items():
            cap = DIMENSION_CAPS.get(dim, 100)
            normalized = min((raw / cap) * 100, 100) if cap > 0 else 0
            dimension_scores[dim] = normalized

            # Only include in composite if there's actual data for this dimension
            if raw > 0:
                active_dimensions[dim] = normalized

        # ── Step 4: Calculate weighted composite score ──
        # Only score dimensions that have actual data
        if active_dimensions:
            total_weight = sum(DIMENSION_WEIGHTS.get(d, 0.1) for d in active_dimensions)
            composite = 0.0
            for dim, dim_score in active_dimensions.items():
                weight = DIMENSION_WEIGHTS.get(dim, 0.1)
                # Re-normalize weights so active dimensions sum to 1.0
                adjusted_weight = weight / total_weight if total_weight > 0 else weight
                composite += dim_score * adjusted_weight
        else:
            composite = 0.0

        final_score = min(int(round(composite)), 100)

        # ── Step 5: Determine severity ──
        severity = "MINIMAL"
        for threshold, label in SEVERITY_BANDS:
            if final_score >= threshold:
                severity = label
                break

        # ── Step 6: Top risky findings ──
        top_findings = sorted(
            confirmed, key=lambda f: len(f.get("risk_tags", [])), reverse=True
        )[:5]

        # ── Step 7: Build dimension detail for the report ──
        dimension_detail = {}
        for dim, dim_score in dimension_scores.items():
            has_data = dim in active_dimensions

            if has_data:
                dim_severity = "MINIMAL"
                for threshold, label in SEVERITY_BANDS:
                    if dim_score >= threshold:
                        dim_severity = label
                        break
                # Use adjusted weight for contribution
                total_weight = sum(DIMENSION_WEIGHTS.get(d, 0.1) for d in active_dimensions)
                adj_weight = DIMENSION_WEIGHTS.get(dim, 0) / total_weight if total_weight > 0 else 0
                dimension_detail[dim] = {
                    "score": round(dim_score, 1),
                    "weight": f"{DIMENSION_WEIGHTS.get(dim, 0)*100:.0f}%",
                    "severity": dim_severity,
                    "weighted_contribution": round(dim_score * adj_weight, 1),
                }
            else:
                dimension_detail[dim] = {
                    "score": "N/A",
                    "weight": f"{DIMENSION_WEIGHTS.get(dim, 0)*100:.0f}%",
                    "severity": "N/A — No Data",
                    "weighted_contribution": 0,
                }

        logger.info("Risk score: %d / 100 — %s", final_score, severity)
        logger.info("  Cyber: %.0f | Reputation: %.0f | Digital: %.0f | Financial: %.0f | Verification: %.0f",
                     dimension_scores.get("cyber", 0), dimension_scores.get("reputation", 0),
                     dimension_scores.get("digital", 0), dimension_scores.get("financial", 0),
                     dimension_scores.get("verification", 0))

        return {
            "risk_score":       final_score,
            "severity":         severity,
            "breakdown":        breakdown,
            "raw_score":        sum(dimension_raw.values()),
            "top_findings":     top_findings,
            "dimensions":       dimension_detail,
        }
