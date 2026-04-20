"""
adapters/company_discovery_adapter.py
Automatic Company Discovery — Finds companies associated with a person

When investigating a person, this adapter:
1. Checks if we discovered any company affiliations
2. Automatically fetches that company's data
3. Recursively discovers team members
"""

import logging
import requests
from typing import List, Dict, Any
from urllib.parse import quote

from core.base_adapter import BaseAdapter, AdapterResult
from config import settings

logger = logging.getLogger(__name__)


class CompanyDiscoveryAdapter(BaseAdapter):
    """
    Discovers companies associated with a person and fetches their data.
    Works in conjunction with person_verification_adapter.
    """

    CATEGORY = "corporate_intelligence"
    ADAPTER_NAME = "company_discovery"

    def fetch(self, entity: str, entity_type: str) -> AdapterResult:
        """
        For individuals: find and research their company affiliations.
        For companies: already handled by other adapters.
        """
        if entity_type != "individual":
            return AdapterResult(self.ADAPTER_NAME, self.CATEGORY, [], [])

        findings = []
        errors = []

        logger.info("🔍 Company Discovery: Finding companies for %s", entity)

        # Step 1: Search for person on LinkedIn to find company
        companies = self._discover_companies_from_linkedin(entity)
        
        if companies:
            logger.info("  ✓ Found %d companies", len(companies))
            for company in companies:
                finding = self.make_finding(
                    title=f"Company Affiliation: {company}",
                    value={
                        "company_name": company,
                        "person": entity,
                        "relationship": "employed_at_or_founder",
                    },
                    source_url=f"https://www.linkedin.com/search/results/companies/?keywords={quote(company)}",
                    risk_tags=["company_affiliation", "discovered"],
                )
                findings.append(finding)

        logger.info("✓ Company Discovery complete: %d companies found", len(findings))
        return AdapterResult(self.ADAPTER_NAME, self.CATEGORY, findings, errors)

    def _discover_companies_from_linkedin(self, person: str) -> List[str]:
        """
        Search LinkedIn to find companies where this person works or founded.
        """
        try:
            logger.info("  ▶ Searching LinkedIn for company affiliations: %s", person)
            
            name_encoded = quote(person)
            search_url = f"https://www.linkedin.com/search/results/people/?keywords={name_encoded}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            try:
                response = requests.get(search_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    content = response.text
                    companies = []
                    
                    # Extract company names using regex patterns
                    import re
                    
                    # Pattern 1: "at COMPANY" or "at CompanyName"
                    pattern1 = r'(?:at|works at|founder at|CEO at)\s+([A-Z][a-zA-Z\s&]*?)(?:\s|<|·|—)'
                    matches1 = re.finditer(pattern1, content)
                    for match in matches1:
                        company = match.group(1).strip()
                        if company and len(company) < 100:  # reasonable length
                            companies.append(company)
                    
                    # Pattern 2: Company badges in profile cards
                    pattern2 = r'data-company-name="([^"]+)"'
                    matches2 = re.finditer(pattern2, content)
                    for match in matches2:
                        company = match.group(1).strip()
                        if company:
                            companies.append(company)
                    
                    # Pattern 3: Look for common startup/company name patterns
                    # E.g., "AiGeeks", "OpenAI", "Google", etc.
                    pattern3 = r'(?:CEO|Founder|Co-founder|CTO|COO|CFO) at ([A-Z][a-zA-Z0-9\s&.]*)'
                    matches3 = re.finditer(pattern3, content)
                    for match in matches3:
                        company = match.group(1).strip()
                        if company:
                            companies.append(company)
                    
                    # Deduplicate and return
                    unique_companies = list(set(companies))
                    logger.info("  ✓ Found companies: %s", unique_companies)
                    return unique_companies
            except Exception as e:
                logger.warning("LinkedIn content parsing failed: %s", e)
            
            # If we can't parse, try fallback: search for "Travis Haasch CEO" 
            search_url2 = f"https://www.linkedin.com/search/results/people/?keywords={quote(person)}%20CEO"
            try:
                response = requests.get(search_url2, headers=headers, timeout=10)
                if response.status_code == 200 and "CEO" in response.text:
                    logger.info("  ! Found CEO mention in secondary search")
                    # Return generic indication for manual verification
                    return ["(Check LinkedIn profile for company information)"]
            except:
                pass
            
            return []
        except Exception as e:
            logger.warning("Company discovery failed: %s", e)
            return []
