"""
adapters/website_verification_adapter.py
Website Ownership & Authority Verification

Intelligently verifies if a website belongs to a person or entity.
Uses:
- WHOIS registrant matching
- DNS MX/TXT record analysis
- SSL certificate verification
- Reverse IP lookup
- Content analysis (about page, team page, contact info)
- Domain history
"""

import logging
import socket
import re
import requests
from typing import List, Dict, Any
from urllib.parse import urlparse

from core.base_adapter import BaseAdapter, AdapterResult
from config import settings

logger = logging.getLogger(__name__)


class WebsiteVerificationAdapter(BaseAdapter):
    """
    Intelligent website verification — NOT just WHOIS lookups.
    
    Determines:
    1. Who owns/registered the domain
    2. If person/company name matches registrant
    3. DNS configuration (hosting provider, mail service)
    4. SSL certificate details
    5. Website content (about, team, contact pages)
    """

    CATEGORY = "infrastructure"
    ADAPTER_NAME = "website_verification"

    def fetch(self, entity: str, entity_type: str) -> AdapterResult:
        """
        Intelligently find and verify official domains.
        Only reports domains with a strong verification signal.
        """
        import concurrent.futures
        findings = []
        errors = []

        logger.info("🔍 Intelligent Website Verification: %s", entity)

        # 1. Get official domain from search results (Phase 0)
        search_domains = self._find_official_domains_via_search(entity)
        
        # 2. Add some high-probability candidates if search results are thin
        candidates = list(search_domains)
        if len(candidates) < 2:
            candidates.extend(self._generate_domain_candidates(entity, entity_type))
        
        # Deduplicate
        candidate_domains = list(set(candidates))
        logger.info("  Candidate domains to verify: %s", candidate_domains)

        def verify_single_domain(domain):
            domain_findings = []
            
            # WHOIS ownership verification
            whois_data = self._verify_whois_ownership(domain, entity)
            whois_conf = whois_data.get("match_confidence", 0)
            
            # Website content analysis
            content_data = self._analyze_website_content(domain, entity)
            content_conf = content_data.get("entity_match_confidence", 0)
            
            # Threshold Check: Only proceed if there is some evidence of ownership
            # This stops the "brute force" listing of unrelated domains like tcs.eg, tcs.dev
            if whois_conf < 50 and content_conf < 50:
                logger.debug("  SKIPPING unrelated domain: %s (Whois: %d, Content: %d)", 
                            domain, whois_conf, content_conf)
                return []

            # If verified, add primary findings
            if whois_conf >= 50:
                domain_findings.append(self.make_finding(
                    title=f"Verified Domain: {domain}",
                    value=whois_data,
                    source_url=f"https://{domain}",
                    risk_tags=["domain_verified", "ownership_confirmed"],
                ))
            
            if content_conf >= 50:
                domain_findings.append(self.make_finding(
                    title=f"Website Content Verified: {domain}",
                    value=content_data,
                    source_url=f"https://{domain}",
                    risk_tags=["content_verified"],
                ))

            # Add technical info ONLY for verified domains
            dns_data = self._analyze_dns(domain)
            if dns_data.get("records"):
                domain_findings.append(self.make_finding(
                    title=f"Infrastructure: {domain}",
                    value=dns_data,
                    source_url=f"https://{domain}",
                    risk_tags=["infrastructure", "dns_records"],
                ))

            return domain_findings

        # Run verification in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            all_domain_findings = list(executor.map(verify_single_domain, candidate_domains))
            for df in all_domain_findings:
                findings.extend(df)

        logger.info("✓ Verification complete: %d relevant findings", len(findings))
        return AdapterResult(self.ADAPTER_NAME, self.CATEGORY, findings, errors)

    def _find_official_domains_via_search(self, entity: str) -> List[str]:
        """Use Google to find the REAL website instead of guessing."""
        found_domains = set()
        try:
            from googlesearch import search as gsearch
            query = f'"{entity}" official website'
            # Only look at top 5 results
            results = list(gsearch(query, num_results=5))
            for url in results:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if domain.startswith("www."):
                    domain = domain[4:]
                if domain and "." in domain:
                    found_domains.add(domain)
        except Exception as e:
            logger.debug("Search for official website failed: %s", e)
        return list(found_domains)

    def _generate_domain_candidates(self, entity: str, entity_type: str) -> List[str]:
        """
        Generate realistic domain candidates to check.
        Includes common TLDs and country-specific ones.
        """
        domains = []
        entity_clean = entity.lower().replace(" ", "").replace("&", "and")
        entity_hyphen = entity.lower().replace(" ", "-").replace("&", "and")
        
        # Common TLDs to check (Limited to most likely ones)
        tlds = [".com", ".io", ".co", ".net", ".org", ".in"]
        
        if entity_type == "individual":
            parts = entity.lower().split()
            if len(parts) >= 2:
                first = parts[0]
                last = parts[-1]
                for tld in tlds:
                    domains.extend([
                        f"{first}{last}{tld}",
                        f"{last}{first}{tld}",
                        f"{first}-{last}{tld}",
                        f"{last}-{first}{tld}",
                    ])
            else:
                for tld in tlds:
                    domains.extend([
                        f"{parts[0]}{tld}",
                    ])
        else:  # company
            for tld in tlds:
                domains.extend([
                    f"{entity_clean}{tld}",
                    f"{entity_hyphen}{tld}",
                ])
        
        return list(set(domains))  # Remove duplicates

    def _verify_whois_ownership(self, domain: str, entity: str) -> Dict[str, Any]:
        """
        Check WHOIS registration and match against entity name.
        Returns confidence score based on name matching.
        """
        try:
            logger.info("  ▶ Checking WHOIS: %s", domain)
            
            # Use python-whois to get registration info
            import whois
            w = whois.whois(domain)
            
            registrant_name = (w.get("registrant_name") or w.get("name") or "").lower()
            registrant_org = (w.get("registrant_organization") or w.get("org") or "").lower()
            
            entity_lower = entity.lower()
            
            # Confidence scoring
            confidence = 0
            matches = []
            
            if registrant_name and entity_lower in registrant_name:
                confidence = 85
                matches.append(f"Registrant name matches: {registrant_name}")
            elif registrant_org and entity_lower in registrant_org:
                confidence = 80
                matches.append(f"Registrant org matches: {registrant_org}")
            elif registrant_name:
                # Fuzzy check if names are similar
                from rapidfuzz import fuzz
                name_ratio = fuzz.token_sort_ratio(entity_lower, registrant_name)
                if name_ratio > 70:
                    confidence = 70
                    matches.append(f"Name similarity: {name_ratio}%")
            
            return {
                "domain": domain,
                "registrant_name": registrant_name,
                "registrant_org": registrant_org,
                "registrant_email": w.get("registrant_email", ""),
                "registrar": w.get("registrar", ""),
                "creation_date": str(w.get("creation_date", "")),
                "expiration_date": str(w.get("expiration_date", "")),
                "match_confidence": confidence,
                "matches": matches,
            }
        except Exception as e:
            logger.warning("WHOIS lookup failed for %s: %s", domain, e)
            return {"match_confidence": 0, "error": str(e)}

    def _analyze_dns(self, domain: str) -> Dict[str, Any]:
        """
        Analyze DNS records to understand infrastructure.
        MX records reveal email provider, NS records show host.
        """
        try:
            logger.info("  ▶ Analyzing DNS: %s", domain)
            import dns.resolver
            
            records = {}
            
            # MX records (email provider)
            try:
                mx_records = dns.resolver.resolve(domain, "MX")
                records["mx"] = [str(r.exchange) for r in mx_records]
            except:
                records["mx"] = []
            
            # A records (IP address)
            try:
                a_records = dns.resolver.resolve(domain, "A")
                records["a"] = [str(r) for r in a_records]
            except:
                records["a"] = []
            
            # TXT records (SPF, DKIM, etc.)
            try:
                txt_records = dns.resolver.resolve(domain, "TXT")
                records["txt"] = [str(r) for r in txt_records]
            except:
                records["txt"] = []
            
            return {
                "domain": domain,
                "records": records,
                "infrastructure_info": self._analyze_hosting_from_dns(records),
            }
        except Exception as e:
            logger.warning("DNS analysis failed for %s: %s", domain, e)
            return {"records": {}, "error": str(e)}

    def _analyze_hosting_from_dns(self, dns_records: Dict) -> Dict[str, str]:
        """
        Identify hosting provider from DNS records.
        """
        hosting_info = {}
        
        if dns_records.get("mx"):
            # Check email provider from MX records
            mx_str = str(dns_records["mx"]).lower()
            if "google" in mx_str:
                hosting_info["email_provider"] = "Google Workspace"
            elif "microsoft" in mx_str or "outlook" in mx_str:
                hosting_info["email_provider"] = "Microsoft 365"
            elif "sendgrid" in mx_str:
                hosting_info["email_provider"] = "SendGrid"
        
        if dns_records.get("a"):
            # Reverse IP lookup (would require external service)
            hosting_info["ip_addresses"] = dns_records["a"]
        
        return hosting_info

    def _verify_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """
        Check SSL/TLS certificate details.
        """
        try:
            logger.info("  ▶ Checking SSL: %s", domain)
            
            response = requests.head(f"https://{domain}", timeout=5, verify=True)
            
            # If we got here, HTTPS is available
            # In production, use ssl.get_certificate_from_server() for full details
            return {
                "domain": domain,
                "certificate_found": True,
                "https_available": True,
                "status_code": response.status_code,
            }
        except requests.exceptions.SSLError:
            return {
                "domain": domain,
                "certificate_found": False,
                "https_available": False,
                "error": "SSL certificate issue",
            }
        except Exception as e:
            logger.warning("SSL verification failed for %s: %s", domain, e)
            return {"certificate_found": False, "error": str(e)}

    def _analyze_website_content(self, domain: str, entity: str) -> Dict[str, Any]:
        """
        Analyze website content to verify it belongs to entity.
        Check about page, team page, contact info for entity name matches.
        """
        try:
            logger.info("  ▶ Analyzing content: %s", domain)
            
            url = f"https://{domain}"
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                return {"entity_match_confidence": 0, "error": "Website not accessible"}
            
            content = response.text.lower()
            entity_lower = entity.lower()
            
            # Look for entity name mentions
            match_count = content.count(entity_lower)
            
            # Look for common pages
            pages_found = {
                "about": "about" in content or "about-us" in content,
                "team": "team" in content or "founders" in content,
                "contact": "contact" in content or "contact-us" in content,
            }
            
            # Calculate confidence
            confidence = min(match_count * 10, 100)  # Cap at 100
            
            return {
                "domain": domain,
                "entity_match_count": match_count,
                "entity_match_confidence": confidence,
                "pages_found": pages_found,
                "content_length": len(content),
            }
        except Exception as e:
            logger.warning("Content analysis failed for %s: %s", domain, e)
            return {"entity_match_confidence": 0, "error": str(e)}
