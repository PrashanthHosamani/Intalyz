"""
adapters/whois_dns_adapter.py
Technical Infrastructure — WHOIS records & DNS history.
Resolves domain registrations and DNS records for the entity.
Includes rate limiting between queries.
"""

import logging
import socket
import time
from typing import List, Optional

import whois
import dns.resolver
import dns.exception

from core.base_adapter import BaseAdapter, AdapterResult
from config import settings

logger = logging.getLogger(__name__)

# Common DNS record types to query
DNS_RECORD_TYPES = ["A", "MX", "NS", "TXT", "CNAME", "AAAA"]


class WhoisDnsAdapter(BaseAdapter):
    """
    Pulls WHOIS registration data and DNS records for domains
    associated with the target entity.
    Applies rate limiting between queries.
    """

    CATEGORY     = "infrastructure"
    ADAPTER_NAME = "whois_dns"

    def fetch(self, entity: str, entity_type: str) -> AdapterResult:
        findings = []
        errors   = []

        # Derive candidate domains from the entity name
        domains = self._candidate_domains(entity)
        logger.info("Candidate domains for %s: %s", entity, domains)
        
        # Get adapter-specific rate limit
        adapter_rate = settings.ADAPTER_RATE_LIMITS.get(self.ADAPTER_NAME, settings.DEFAULT_RATE_LIMIT)

        for domain in domains:
            # Apply rate limiting before each domain
            elapsed = time.time() - self._last_request_time
            if elapsed < adapter_rate:
                delay = adapter_rate - elapsed
                logger.debug("Rate limiting: sleeping %.1fs", delay)
                time.sleep(delay)
            
            self._last_request_time = time.time()
            self._request_count += 1
            
            # ── WHOIS ──────────────────────────────────────────────────────
            try:
                logger.debug("WHOIS lookup: %s", domain)
                w = whois.whois(domain)
                if w and w.domain_name:
                    # Confidence check: Only report if name or org matches
                    registrant = (getattr(w, 'registrant_name', '') or getattr(w, 'name', '') or '').lower()
                    org = (getattr(w, 'org', '') or getattr(w, 'registrant_organization', '') or '').lower()
                    entity_lower = entity.lower()
                    
                    if entity_lower not in registrant and entity_lower not in org:
                        logger.debug("  SKIPPING WHOIS for unrelated domain: %s", domain)
                        # Still do DNS check but we might want to skip it too if unrelated
                    else:
                        source_url = f"https://whois.domaintools.com/{domain}"
                        findings.append(
                            self.make_finding(
                                title="WHOIS Record (Verified)",
                                value={
                                    "domain":       domain,
                                    "registrar":    w.registrar if hasattr(w, 'registrar') else None,
                                    "registrant":   registrant,
                                    "org":          org,
                                    "created":      str(w.creation_date) if hasattr(w, 'creation_date') else None,
                                    "expires":      str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                                    "name_servers": list(w.name_servers) if hasattr(w, 'name_servers') and w.name_servers else [],
                                },
                                source_url=source_url,
                                risk_tags=self._whois_risk_tags(w),
                            )
                        )
            except Exception as exc:
                msg = f"WHOIS failed [{domain}]: {exc}"
                logger.debug(msg)
                errors.append(msg)

            # ── DNS Records ────────────────────────────────────────────────
            # Only perform DNS records if the domain was verified above
            is_verified = any(f.get("title") == "WHOIS Record (Verified)" and f.get("value", {}).get("domain") == domain for f in findings)
            
            if is_verified:
                for rtype in DNS_RECORD_TYPES:
                    try:
                        logger.debug("DNS %s lookup: %s", rtype, domain)
                        answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                        records = [str(r) for r in answers]
                        findings.append(
                            self.make_finding(
                                title=f"DNS {rtype} Record",
                                value={"domain": domain, "type": rtype, "records": records},
                                source_url=f"https://dnschecker.org/#A/{domain}",
                                risk_tags=self._dns_risk_tags(rtype, records),
                            )
                        )
                    except (dns.exception.DNSException, Exception):
                        pass  # Not all record types exist — this is expected
            else:
                logger.debug("  SKIPPING DNS for unverified domain: %s", domain)

        logger.info("✓ %s found %d records", self.ADAPTER_NAME, len(findings))
        return AdapterResult(self.ADAPTER_NAME, self.CATEGORY, findings, errors)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _candidate_domains(entity: str) -> List[str]:
        """
        Generate plausible domain names from entity name.
        e.g. "Acme Corp" → ["acmecorp.com", "acme.com", "acme-corp.com"]
        """
        slug = entity.lower().strip()
        # Remove common suffixes
        for suffix in [" inc", " llc", " ltd", " corp", " co", " company"]:
            slug = slug.replace(suffix, "")
        slug = slug.strip()
        no_space   = slug.replace(" ", "")
        hyphenated = slug.replace(" ", "-")
        candidates = []
        max_domains = settings.WHOIS_DNS_MAX_DOMAINS
        for tld in [".com", ".io", ".co", ".net", ".org"]:
            if len(candidates) >= max_domains:
                break
            candidates.append(no_space + tld)
            if hyphenated != no_space and len(candidates) < max_domains:
                candidates.append(hyphenated + tld)
        return candidates[:max_domains]

    @staticmethod
    def _whois_risk_tags(w) -> List[str]:
        tags = []
        try:
            privacy_enabled = hasattr(w, 'privacy') and w.privacy
            privacy_org = hasattr(w, 'org') and w.org and "privacy" in str(w.org).lower()
            if privacy_enabled or privacy_org:
                tags.append("whois_privacy")
        except Exception:
            pass
        return tags

    @staticmethod
    def _dns_risk_tags(rtype: str, records: List[str]) -> List[str]:
        tags = []
        if rtype == "TXT":
            for r in records:
                if "spf" not in r.lower() and "dkim" not in r.lower():
                    tags.append("dns_anomaly")
        return tags
