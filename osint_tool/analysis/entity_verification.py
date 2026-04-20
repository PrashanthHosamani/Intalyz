"""
analysis/entity_verification.py
Entity Pre-Verification — Checks if entity is real and searchable BEFORE running adapters

This prevents wasting resources on non-existent or unsearchable entities.
Only entities that pass verification proceed to full adapter analysis.
"""

import logging
import requests
from typing import Dict, Any, Tuple
from urllib.parse import quote
import re

logger = logging.getLogger(__name__)


class EntityVerifier:
    """
    Pre-verification for entities to determine if they're worth investigating.
    
    Checks:
    1. Does entity exist? (Google search confirms mentions)
    2. Is entity searchable? (Has online presence)
    3. What type of entity? (Individual with profile, company with website, etc.)
    4. Initial confidence in entity reality (0-100)
    """
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def verify(self, entity: str, entity_type: str) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Verify if entity exists and is worth investigating.
        
        Args:
            entity: Entity name to verify
            entity_type: 'individual' or 'company'
        
        Returns:
            (is_verified: bool, confidence: float 0-100, details: dict)
        """
        logger.info("🔍 Entity Verification: %s (%s)", entity, entity_type)
        
        if entity_type == "individual":
            return self._verify_individual(entity)
        elif entity_type == "company":
            return self._verify_company(entity)
        
        return False, 0, {"reason": "Unknown entity type"}
    
    def _verify_individual(self, person: str) -> Tuple[bool, float, Dict[str, Any]]:
        """Verify if individual exists and is searchable in parallel."""
        import concurrent.futures
        logger.info("  ▶ Verifying individual: %s (Parallel)", person)
        
        confidence = 0
        findings = {}
        
        # Define tasks for parallel execution
        tasks = {
            "linkedin": lambda: self._check_linkedin_profile(person),
            "github": lambda: self._check_github_profile(person),
            "google_mentions": lambda: self._check_google_mentions(person),
            "social_media": lambda: self._check_social_media(person),
            "email": lambda: self._check_email_presence(person)
        }
        
        weights = {
            "linkedin": 35,
            "github": 25,
            "google_mentions": 20,
            "social_media": 15,
            "email": 5
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_source = {executor.submit(fn): source for source, fn in tasks.items()}
            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    found = future.result()
                    if found:
                        confidence += weights[source]
                        findings[source] = found
                        logger.info("    ✓ %s found", source.replace("_", " ").title())
                except Exception as e:
                    logger.debug("%s verification failed: %s", source, e)
        
        is_verified = confidence >= 40
        
        result = {
            "confidence": min(confidence, 100),
            "findings": findings,
            "recommendation": "proceed" if is_verified else "skip",
            "reason": f"Found {len(findings)} verification sources" if findings else "No verification sources found"
        }
        
        logger.info("  ✓ Individual verification: %s (confidence: %d%%)", 
                   "PASS" if is_verified else "FAIL", confidence)
        
        return is_verified, confidence, result
    
    def _verify_company(self, company: str) -> Tuple[bool, float, Dict[str, Any]]:
        """Verify if company exists and is searchable in parallel."""
        import concurrent.futures
        logger.info("  ▶ Verifying company: %s (Parallel)", company)
        
        confidence = 0
        findings = {}
        
        # Define tasks for parallel execution
        tasks = {
            "website": lambda: self._check_company_website(company),
            "linkedin": lambda: self._check_linkedin_company(company),
            "public_info": lambda: self._check_public_company_info(company),
            "crunchbase": lambda: self._check_crunchbase(company)
        }
        
        weights = {
            "website": 40,
            "linkedin": 30,
            "public_info": 20,
            "crunchbase": 10
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_source = {executor.submit(fn): source for source, fn in tasks.items()}
            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    found = future.result()
                    if found:
                        confidence += weights[source]
                        findings[source] = found
                        logger.info("    ✓ %s found", source.replace("_", " ").title())
                except Exception as e:
                    logger.debug("%s verification failed: %s", source, e)
        
        is_verified = confidence >= 50
        
        result = {
            "confidence": min(confidence, 100),
            "findings": findings,
            "recommendation": "proceed" if is_verified else "skip",
            "reason": f"Found {len(findings)} verification sources" if findings else "No verification sources found"
        }
        
        logger.info("  ✓ Company verification: %s (confidence: %d%%)",
                   "PASS" if is_verified else "FAIL", confidence)
        
        return is_verified, confidence, result
    
    def _check_linkedin_profile(self, person: str) -> bool:
        """Check if person has LinkedIn profile."""
        try:
            name_encoded = quote(person)
            url = f"https://www.linkedin.com/search/results/people/?keywords={name_encoded}"
            
            response = requests.get(url, headers=self.headers, timeout=3)
            if response.status_code == 200 and "No results found" not in response.text:
                return True
        except Exception:
            pass
        return False
    
    def _check_github_profile(self, person: str) -> bool:
        """Check if person has GitHub profile in parallel."""
        import concurrent.futures
        try:
            variations = [
                person.lower().replace(" ", ""),
                person.lower().replace(" ", "-"),
                person.split()[0].lower() if " " in person else person.lower(),
            ]
            
            def check_user(username):
                url = f"https://api.github.com/users/{username}"
                resp = requests.get(url, headers=self.headers, timeout=3)
                return resp.status_code == 200 and resp.json().get("login")

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                results = list(executor.map(check_user, variations))
                return any(results)
        except Exception:
            pass
        return False
    
    def _check_google_mentions(self, person: str) -> bool:
        """Check if person is mentioned on web in parallel."""
        import concurrent.futures
        try:
            searches = [person, f'"{person}"']
            
            def check_query(query):
                url = f"https://www.google.com/search?q={quote(query)}"
                resp = requests.get(url, headers=self.headers, timeout=3)
                return resp.status_code == 200 and len(resp.text) > 10000

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(check_query, searches))
                return any(results)
        except Exception:
            pass
        return False
    
    def _check_social_media(self, person: str) -> bool:
        """Check if person has social media presence in parallel."""
        import concurrent.futures
        try:
            username = person.lower().replace(" ", "")
            platforms = {
                "twitter": f"https://x.com/{username}",
                "instagram": f"https://instagram.com/{username}/"
            }
            
            def check_url(url):
                try:
                    resp = requests.head(url, headers=self.headers, timeout=3)
                    return resp.status_code == 200
                except:
                    return False

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(check_url, platforms.values()))
                return any(results)
        except Exception:
            pass
        return False
    
    def _check_email_presence(self, person: str) -> bool:
        """Check if person's email appears in search results."""
        try:
            parts = person.lower().split()
            email = f"{parts[0]}.{parts[-1]}@gmail.com" if len(parts) > 1 else f"{parts[0]}@gmail.com"
            url = f"https://www.google.com/search?q={quote(email)}"
            response = requests.get(url, headers=self.headers, timeout=3)
            return response.status_code == 200 and len(response.text) > 10000
        except Exception:
            pass
        return False
    
    def _check_company_website(self, company: str) -> bool:
        """Check if company website exists in parallel."""
        import concurrent.futures
        try:
            tlds = ['com', 'io', 'in', 'co', 'org', 'net']
            company_clean = company.lower().replace(" ", "").replace("&", "and")
            
            def check_domain(tld):
                url = f"https://{company_clean}.{tld}"
                try:
                    resp = requests.head(url, headers=self.headers, timeout=3)
                    return resp.status_code in [200, 301, 302]
                except:
                    return False

            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                results = list(executor.map(check_domain, tlds))
                return any(results)
        except Exception:
            pass
        return False
    
    def _check_linkedin_company(self, company: str) -> bool:
        """Check if company has LinkedIn page."""
        try:
            url = f"https://www.linkedin.com/search/results/companies/?keywords={quote(company)}"
            response = requests.get(url, headers=self.headers, timeout=3)
            return response.status_code == 200 and "No results found" not in response.text
        except Exception:
            pass
        return False
    
    def _check_public_company_info(self, company: str) -> bool:
        """Check if company has public information."""
        try:
            url = f"https://www.google.com/search?q={quote(company + ' company')}"
            response = requests.get(url, headers=self.headers, timeout=3)
            return response.status_code == 200 and len(response.text) > 10000
        except Exception:
            pass
        return False
    
    def _check_crunchbase(self, company: str) -> bool:
        """Check if company is on Crunchbase."""
        try:
            company_slug = company.lower().replace(" ", "-").replace("&", "and")
            url = f"https://www.crunchbase.com/organization/{company_slug}"
            response = requests.head(url, headers=self.headers, timeout=3)
            return response.status_code == 200
        except Exception:
            pass
        return False
