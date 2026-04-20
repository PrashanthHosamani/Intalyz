"""
adapters/company_intel_adapter.py
Corporate Intelligence — Financial data (Yahoo Finance), public discussions
(Reddit), and verification link generation for due diligence.
All sources are 100% free with no API keys required.
"""

import logging
import time
import re
import urllib.parse
from typing import List, Dict, Any

from core.base_adapter import BaseAdapter, AdapterResult
from config import settings

logger = logging.getLogger(__name__)


class CompanyIntelAdapter(BaseAdapter):
    """
    Gathers corporate intelligence from free public sources:
      1. Yahoo Finance (via yfinance)  — financials, balance sheet
      2. Reddit public search          — discussions and sentiment
      3. Verification link generator   — MCA, GST, Google Maps, LinkedIn, etc.
    """

    CATEGORY     = "corporate_intelligence"
    ADAPTER_NAME = "company_intel"

    def fetch(self, entity: str, entity_type: str) -> AdapterResult:
        import concurrent.futures
        findings: List[Dict[str, Any]] = []
        errors:   List[str]            = []

        adapter_rate = settings.ADAPTER_RATE_LIMITS.get(
            self.ADAPTER_NAME, settings.DEFAULT_RATE_LIMIT
        )

        def run_financials():
            return self._check_financials(entity, errors)

        def run_reddit():
            return self._check_reddit(entity, adapter_rate, errors)

        def run_verification():
            return self._generate_verification_links(entity, entity_type, errors)

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            f_fin   = executor.submit(run_financials)
            f_red   = executor.submit(run_reddit)
            f_ver   = executor.submit(run_verification)

            findings.extend(f_fin.result())
            findings.extend(f_red.result())
            findings.extend(f_ver.result())

        logger.info("✓ %s found %d records", self.ADAPTER_NAME, len(findings))
        return AdapterResult(self.ADAPTER_NAME, self.CATEGORY, findings, errors)

    # ── Yahoo Finance ─────────────────────────────────────────────────────────

    def _check_financials(self, entity: str, errors: list) -> list:
        findings = []

        # STEP 1: Try yfinance for publicly listed companies
        yfinance_found = self._try_yfinance(entity, findings, errors)

        # STEP 2: If yfinance failed, try scraping financial data from news/web
        if not yfinance_found:
            self._try_web_financials(entity, findings, errors)

        return findings

    def _try_yfinance(self, entity: str, findings: list, errors: list) -> bool:
        """Try Yahoo Finance. Returns True if data was found."""
        try:
            import yfinance as yf
            ticker_candidates = self._guess_tickers(entity)

            for ticker_symbol in ticker_candidates:
                try:
                    ticker = yf.Ticker(ticker_symbol)
                    info = ticker.info

                    if not info or info.get("regularMarketPrice") is None:
                        continue

                    # Company overview
                    findings.append(
                        self.make_finding(
                            title="Financial Profile",
                            value={
                                "ticker":          ticker_symbol,
                                "name":            info.get("longName", entity),
                                "sector":          info.get("sector", "N/A"),
                                "industry":        info.get("industry", "N/A"),
                                "market_cap":      self._fmt_number(info.get("marketCap")),
                                "enterprise_value": self._fmt_number(info.get("enterpriseValue")),
                                "current_price":   info.get("regularMarketPrice"),
                                "currency":        info.get("currency", "USD"),
                                "website":         info.get("website", "N/A"),
                                "employees":       self._fmt_number(info.get("fullTimeEmployees")),
                                "country":         info.get("country", "N/A"),
                                "exchange":        info.get("exchange", "N/A"),
                            },
                            source_url=f"https://finance.yahoo.com/quote/{ticker_symbol}/",
                            risk_tags=[],
                        )
                    )

                    # Income statement
                    revenue      = info.get("totalRevenue")
                    net_income   = info.get("netIncomeToCommon")
                    profit_margin = info.get("profitMargins")
                    ebitda       = info.get("ebitda")

                    if revenue or net_income:
                        findings.append(
                            self.make_finding(
                                title="Income Statement Summary",
                                value={
                                    "total_revenue":  self._fmt_number(revenue),
                                    "net_income":     self._fmt_number(net_income),
                                    "profit_margin":  f"{profit_margin*100:.1f}%" if profit_margin else "N/A",
                                    "ebitda":         self._fmt_number(ebitda),
                                    "revenue_growth": f"{info.get('revenueGrowth', 0)*100:.1f}%" if info.get('revenueGrowth') else "N/A",
                                },
                                source_url=f"https://finance.yahoo.com/quote/{ticker_symbol}/financials/",
                                risk_tags=self._financial_risk_tags(info),
                            )
                        )

                    # Balance sheet
                    total_assets = info.get("totalAssets")
                    total_debt   = info.get("totalDebt")
                    total_cash   = info.get("totalCash")

                    if total_assets or total_debt:
                        debt_to_equity = info.get("debtToEquity")
                        findings.append(
                            self.make_finding(
                                title="Balance Sheet Summary",
                                value={
                                    "total_assets": self._fmt_number(total_assets),
                                    "total_debt":   self._fmt_number(total_debt),
                                    "total_cash":   self._fmt_number(total_cash),
                                    "debt_to_equity": f"{debt_to_equity:.2f}" if debt_to_equity else "N/A",
                                    "book_value":   self._fmt_number(info.get("bookValue")),
                                },
                                source_url=f"https://finance.yahoo.com/quote/{ticker_symbol}/balance-sheet/",
                                risk_tags=["high_debt"] if debt_to_equity and debt_to_equity > 200 else [],
                            )
                        )

                    return True  # Found data

                except Exception:
                    continue

        except ImportError:
            errors.append("yfinance not installed — skipping Yahoo Finance")
        except Exception as exc:
            logger.debug("yfinance error: %s", exc)

        return False  # No data found

    def _try_web_financials(self, entity: str, findings: list, errors: list):
        """Scrape financial data from news articles and public sources for private companies."""
        import re
        headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}
        encoded = urllib.parse.quote_plus(entity)

        financial_data = {}
        source_urls = []

        # SOURCE 1: Search Google for financial news
        try:
            query = urllib.parse.quote_plus(f"{entity} revenue profit crore financial results FY")
            url = f"https://www.google.com/search?q={query}&num=5"
            resp = self._session.get(url, headers=headers, timeout=10)

            if resp.status_code == 200:
                text = resp.text

                # Extract snippets from Google results
                # Look for revenue/profit figures in ₹ Crore or $ format
                crore_patterns = [
                    r'(?:revenue|turnover|income|sales)[\s:]*(?:of\s+)?(?:₹|Rs\.?|INR)?\s*([\d,\.]+)\s*(?:crore|cr)',
                    r'(?:₹|Rs\.?|INR)\s*([\d,\.]+)\s*(?:crore|cr)[\s]*(?:revenue|turnover)',
                    r'(?:net\s+)?profit[\s:]*(?:of\s+)?(?:₹|Rs\.?|INR)?\s*([\d,\.]+)\s*(?:crore|cr)',
                    r'(?:₹|Rs\.?|INR)\s*([\d,\.]+)\s*(?:crore|cr)[\s]*(?:net\s+)?profit',
                ]

                text_lower = text.lower()
                for pattern in crore_patterns:
                    matches = re.findall(pattern, text_lower, re.IGNORECASE)
                    if matches:
                        for m in matches[:2]:
                            val = m.replace(",", "")
                            try:
                                num = float(val)
                                if "revenue" in pattern or "turnover" in pattern or "sales" in pattern:
                                    financial_data["revenue"] = f"₹{val} Crore"
                                elif "profit" in pattern:
                                    financial_data["net_profit"] = f"₹{val} Crore"
                            except ValueError:
                                pass

                # Extract source URLs from Google results
                url_pattern = r'https?://(?:www\.)?(?:economictimes|moneycontrol|livemint|ndtv|entrackr|inc42|yourstory|business-standard|financialexpress)[^\s"<>]*'
                source_matches = re.findall(url_pattern, text)
                for s_url in source_matches[:3]:
                    s_url = s_url.split("&amp;")[0].split("\\")[0].rstrip(".,;)")
                    if s_url not in source_urls:
                        source_urls.append(s_url)

        except Exception as exc:
            logger.debug("Google financial search error: %s", exc)

        # SOURCE 2: Try Tofler search page
        try:
            time.sleep(1)
            tofler_url = f"https://www.tofler.in/search?q={encoded}"
            resp = self._session.get(tofler_url, headers=headers, timeout=8)
            if resp.status_code == 200:
                tofler_text = resp.text.lower()
                # Check if entity appears in results
                if entity.lower() in tofler_text:
                    financial_data["tofler_available"] = "Yes"
                    # Try to extract company URL from Tofler results
                    tofler_link_match = re.search(
                        rf'href="(/[^"]*{re.escape(entity.lower().replace(" ", "-"))}[^"]*)"',
                        resp.text, re.IGNORECASE
                    )
                    if tofler_link_match:
                        tofler_company_url = f"https://www.tofler.in{tofler_link_match.group(1)}"
                        source_urls.append(tofler_company_url)
                    else:
                        source_urls.append(tofler_url)
        except Exception:
            pass

        # SOURCE 3: Try Wikipedia for company overview
        try:
            time.sleep(0.5)
            wiki_url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(entity)}"
            resp = self._session.get(wiki_url, headers=headers, timeout=5)
            if resp.status_code == 200:
                wiki_data = resp.json()
                description = wiki_data.get("extract", "")
                if description and len(description) > 50:
                    financial_data["company_type"] = wiki_data.get("description", "N/A")
                    # Extract any revenue figures from Wikipedia
                    revenue_match = re.search(
                        r'(?:revenue|income).*?(?:₹|Rs\.?|\$|USD|INR)\s*([\d,\.]+)\s*(?:crore|billion|million|cr|bn|mn)',
                        description, re.IGNORECASE
                    )
                    if revenue_match:
                        financial_data["revenue_wiki"] = revenue_match.group(0).strip()
        except Exception:
            pass

        # Generate financial overview links
        link_data = {
            "tofler": f"https://www.tofler.in/search?q={encoded}",
            "zauba_corp": f"https://www.zaubacorp.com/company-list?q={encoded}",
            "google_finance_news": f"https://www.google.com/search?q={encoded}+financial+results+revenue+profit",
            "moneycontrol": f"https://www.moneycontrol.com/stocks/cptmarket/compsearchnew.php?search_data={encoded}",
        }

        if financial_data:
            # Build the value dict
            value = {
                "data_source": "News reports & public filings (not stock exchange)",
                "company_status": "Likely PRIVATE — not listed on stock exchanges",
            }
            value.update(financial_data)
            value["verification_links"] = " | ".join(source_urls[:3]) if source_urls else "See links below"

            findings.append(
                self.make_finding(
                    title="Financial Profile",
                    value=value,
                    source_url=source_urls[0] if source_urls else link_data["google_finance_news"],
                    risk_tags=[],
                )
            )

        # Always add financial investigation links
        findings.append(
            self.make_finding(
                title="Financial Sources",
                value={
                    "note": f"{'Financial data extracted from news reports.' if financial_data else 'No financial data found via automated search.'} "
                            f"For official filings, check these sources manually:",
                    "tofler": link_data["tofler"],
                    "zauba_corp": link_data["zauba_corp"],
                    "moneycontrol": link_data["moneycontrol"],
                    "google_search": link_data["google_finance_news"],
                    "mca_portal": "https://www.mca.gov.in/mcafoportal/showdiraborSearchPage.do",
                },
                source_url=link_data["tofler"],
                risk_tags=[],
            )
        )

    # ── Reddit Discussions ────────────────────────────────────────────────────

    def _check_reddit(self, entity: str, adapter_rate: float, errors: list) -> list:
        findings = []
        try:
            search_url = "https://www.reddit.com/search.json"
            params = {
                "q": f'"{entity}"',
                "sort": "relevance",
                "limit": 10,
                "t": "year",
            }
            headers = {
                "User-Agent": "OSINT-Tool/1.0 (Educational Research)"
            }

            logger.debug("Reddit search: %s", entity)
            time.sleep(adapter_rate)

            resp = self._session.get(
                search_url, params=params, headers=headers,
                timeout=settings.DEFAULT_TIMEOUT
            )

            if resp.status_code == 200:
                data = resp.json()
                posts = data.get("data", {}).get("children", [])

                for post_wrapper in posts[:8]:
                    post = post_wrapper.get("data", {})
                    title = post.get("title", "")
                    subreddit = post.get("subreddit", "")
                    score = post.get("score", 0)
                    num_comments = post.get("num_comments", 0)
                    permalink = post.get("permalink", "")
                    created_utc = post.get("created_utc", 0)

                    # Determine sentiment from title
                    risk_tags = self._discussion_risk_tags(title)

                    findings.append(
                        self.make_finding(
                            title="Reddit Discussion",
                            value={
                                "title":        title[:150],
                                "subreddit":    f"r/{subreddit}",
                                "upvotes":      score,
                                "comments":     num_comments,
                                "url":          f"https://reddit.com{permalink}",
                            },
                            source_url=f"https://reddit.com{permalink}",
                            risk_tags=risk_tags,
                        )
                    )
            elif resp.status_code == 429:
                errors.append("Reddit rate limited — try again later")
            else:
                errors.append(f"Reddit search returned status {resp.status_code}")

        except Exception as exc:
            msg = f"Reddit search error: {exc}"
            logger.warning(msg)
            errors.append(msg)

        return findings

    def _generate_verification_links(self, entity: str, entity_type: str, errors: list) -> list:
        """Search platforms for the entity in parallel for speed."""
        import concurrent.futures
        findings = []
        encoded = urllib.parse.quote_plus(entity)
        clean_name = re.sub(r'[^a-zA-Z0-9]', '', entity).lower()
        headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}

        verification_checks = [
            {"factor": "Website", "fn": lambda: self._verify_website(entity, headers)},
            {"factor": "LinkedIn Profile", "fn": lambda: self._check_direct_url(entity, f"https://www.linkedin.com/company/{clean_name}/", headers, "linkedin.com/company")},
            {"factor": "Glassdoor Reviews", "fn": lambda: self._search_google_site(entity, "glassdoor.com", headers)},
            {"factor": "Crunchbase Profile", "fn": lambda: self._check_direct_url(entity, f"https://www.crunchbase.com/organization/{clean_name}", headers, "crunchbase.com")},
            {"factor": "Twitter / X Profile", "fn": lambda: self._check_direct_url(entity, f"https://x.com/{clean_name}", headers, "twitter.com")},
            {"factors": ["Legal Existence (MCA Portal)", "Age / Establishment", "Ownership"], "fn": lambda: self._search_google_site(entity, "mca.gov.in", headers)},
            {"factor": "Tax Compliance (GST Portal)", "fn": lambda: self._search_google_site(entity, "gst.gov.in", headers)},
            {"factor": "Tofler Financial Data", "fn": lambda: self._search_google_site(entity, "tofler.in", headers)},
            {"factor": "Zauba Corp Data", "fn": lambda: self._search_google_site(entity, "zaubacorp.com", headers)},
            {"factor": "SEC EDGAR Filing (US)", "fn": lambda: self._check_sec_edgar(entity, headers)},
            {"factor": "Companies House (UK)", "fn": lambda: self._check_companies_house(entity, headers)},
            {"factor": "Physical Presence (Google Maps)", "fn": lambda: {"status": "SEARCH_LINK", "url": f"https://www.google.com/maps/search/{encoded}", "detail": "Manual check"}},
        ]

        def _run_check(check):
            try:
                # Add a small staggered start to avoid immediate burst
                idx = verification_checks.index(check)
                if idx > 0:
                    time.sleep(idx * 0.2)
                
                res = check["fn"]()
                status = res.get("status", "NOT_FOUND")
                url = res.get("url", "N/A")
                detail = res.get("detail", "")
                
                label = "✅ VERIFIED" if status == "FOUND" else ("🔗 MANUAL CHECK" if status == "SEARCH_LINK" else "❌ NOT FOUND")
                
                local_findings = []
                factors = check.get("factors", [check.get("factor")])
                for f in factors:
                    local_findings.append(self.make_finding(
                        title="Verification Result",
                        value={"factor": f, "status": label, "url": url, "detail": detail},
                        source_url=url, risk_tags=[]
                    ))
                return local_findings
            except Exception as exc:
                return [self.make_finding(
                    title="Verification Result",
                    value={"factor": check.get("factor", "Unknown"), "status": "⚠️ ERROR", "url": "N/A", "detail": str(exc)[:100]},
                    source_url="N/A", risk_tags=[]
                )]

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            future_results = list(executor.map(_run_check, verification_checks))
            for res_list in future_results:
                findings.extend(res_list)

        return findings

    # Indicators that a domain is parked/placeholder — not a real company site
    PARKED_INDICATORS = [
        "is parked", "parked free", "parked domain", "domain parking",
        "get this domain", "buy this domain", "this domain is for sale",
        "domain for sale", "hugedomains", "godaddy", "sedo.com",
        "namecheap", "afternic", "undeveloped", "dan.com",
        "this page is under construction", "coming soon",
        "website coming soon", "site under construction",
        "placeholder", "parked by", "courtesy of godaddy",
        "this site can't be reached", "domaincontrol",
        "sedoparking", "above.com", "bodis.com",
    ]

    def _verify_website(self, entity: str, headers: dict) -> dict:
        """Check if entity has a REAL working website (not parked/placeholder)."""
        import re
        clean = re.sub(r'[^a-zA-Z0-9]', '', entity).lower()
        domains_to_try = [f"{clean}.com", f"{clean}.io", f"{clean}.in", f"{clean}.co"]

        for domain in domains_to_try:
            try:
                resp = self._session.get(
                    f"https://{domain}", headers=headers,
                    timeout=8, allow_redirects=True
                )
                if resp.status_code < 400:
                    page_text = resp.text[:10000]
                    page_lower = page_text.lower()
                    entity_lower = entity.lower()

                    # Extract page title
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', page_text, re.IGNORECASE | re.DOTALL)
                    page_title = title_match.group(1).strip()[:120] if title_match else "No title"

                    # CHECK 1: Is this a parked/placeholder domain?
                    is_parked = any(indicator in page_lower for indicator in self.PARKED_INDICATORS)

                    if is_parked:
                        return {
                            "status": "NOT_FOUND",
                            "url": f"https://{domain}",
                            "detail": f"PARKED DOMAIN — Not a real website. Title: '{page_title}'. Domain is for sale or placeholder.",
                        }

                    # CHECK 2: Does the page have real content? (not just a blank page)
                    # Strip HTML tags and check if there's substantial text
                    stripped = re.sub(r'<[^>]+>', ' ', page_text)
                    word_count = len(stripped.split())
                    if word_count < 30:
                        return {
                            "status": "NOT_FOUND",
                            "url": f"https://{domain}",
                            "detail": f"Empty/minimal page ({word_count} words). Not a real company website.",
                        }

                    # CHECK 3: Does entity name appear on the page?
                    if entity_lower in page_lower:
                        return {
                            "status": "FOUND",
                            "url": f"https://{domain}",
                            "detail": f"VERIFIED — Real website. Title: '{page_title}'. Entity name confirmed on page.",
                        }
                    else:
                        return {
                            "status": "FOUND",
                            "url": f"https://{domain}",
                            "detail": f"Site is live ({word_count} words) but entity name not found on page. Title: '{page_title}'. Could not fully verify ownership.",
                        }
            except Exception:
                continue

        return {
            "status": "NOT_FOUND",
            "url": "N/A",
            "detail": f"No website found at {', '.join(domains_to_try)}. Could not verify.",
        }

    def _check_direct_url(self, entity: str, direct_url: str, headers: dict, fallback_site: str = "") -> dict:
        """Try direct URL first, then fall back to Google site search."""
        import re
        entity_lower = entity.lower()

        # STEP 1: Try the direct URL
        try:
            resp = self._session.get(direct_url, headers=headers, timeout=8, allow_redirects=True)
            if resp.status_code < 400:
                page_text = resp.text[:10000]
                page_lower = page_text.lower()

                title_match = re.search(r'<title[^>]*>(.*?)</title>', page_text, re.IGNORECASE | re.DOTALL)
                page_title = title_match.group(1).strip()[:120] if title_match else "N/A"

                # Check for parked/error pages
                is_parked = any(ind in page_lower for ind in self.PARKED_INDICATORS)
                if is_parked:
                    pass  # Fall through to Google search
                elif entity_lower in page_lower:
                    return {
                        "status": "FOUND",
                        "url": direct_url,
                        "detail": f"VERIFIED — Direct URL confirmed. Title: '{page_title}'",
                    }
                elif "page not found" not in page_lower and "404" not in page_title.lower():
                    # Page exists but entity name might be slightly different
                    stripped = re.sub(r'<[^>]+>', ' ', page_text)
                    word_count = len(stripped.split())
                    if word_count > 50:
                        return {
                            "status": "FOUND",
                            "url": direct_url,
                            "detail": f"Profile page exists ({word_count} words). Title: '{page_title}'",
                        }
            elif resp.status_code == 404:
                pass  # Direct URL not found, try Google
            elif resp.status_code == 999:
                # LinkedIn blocks automated requests with 999
                # Still report the URL since it likely exists
                return {
                    "status": "FOUND",
                    "url": direct_url,
                    "detail": f"Profile URL exists (blocked by anti-bot). Visit manually: {direct_url}",
                }
        except Exception:
            pass  # Fall through to Google search

        # STEP 2: Fall back to Google site search
        if fallback_site:
            return self._search_google_site(entity, fallback_site, headers)

        return {
            "status": "NOT_FOUND",
            "url": direct_url,
            "detail": f"Could not verify at {direct_url}",
        }

    def _search_google_site(self, entity: str, site: str, headers: dict) -> dict:
        """Search Google for 'entity site:domain', visit the result, and verify content matches."""
        try:
            import re
            # Use exact match quotes around entity to prevent Google from returning generic pages
            query = urllib.parse.quote_plus(f'"{entity}" site:{site}')
            url = f"https://www.google.com/search?q={query}&num=3"
            resp = self._session.get(url, headers=headers, timeout=10)

            if resp.status_code == 200:
                text = resp.text
                pattern = rf'https?://(?:www\.)?{re.escape(site)}[^\s"<>]*'
                matches = re.findall(pattern, text)

                clean_urls = []
                for m in matches:
                    if "google.com" not in m and len(m) > 20:
                        m = m.split("&amp;")[0].split("\\")[0].rstrip(".,;)")
                        if m not in clean_urls:
                            clean_urls.append(m)

                if clean_urls:
                    found_url = clean_urls[0]

                    # Many government and financial portals block automated requests (CAPTCHA/403)
                    # If Google has indexed an EXACT MATCH for the entity on these domains, we trust it.
                    hard_to_scrape = ["mca.gov.in", "gst.gov.in", "tofler.in", "zaubacorp.com"]
                    if any(h in site for h in hard_to_scrape):
                        # Ensure Google didn't say "Missing: entity"
                        if "must include:" not in text.lower() and "did not match any documents" not in text.lower():
                            return {
                                "status": "FOUND",
                                "url": found_url,
                                "detail": f"VERIFIED (via Google Index) — Official record found on {site}",
                            }

                    # STEP 2: Visit the page and verify (for regular sites)
                    try:
                        time.sleep(1)
                        page_resp = self._session.get(found_url, headers=headers, timeout=8, allow_redirects=True)
                        if page_resp.status_code < 400:
                            page_text = page_resp.text[:8000]
                            page_lower = page_text.lower()
                            entity_lower = entity.lower()

                            title_match = re.search(r'<title[^>]*>(.*?)</title>', page_text, re.IGNORECASE | re.DOTALL)
                            page_title = title_match.group(1).strip()[:120] if title_match else "N/A"

                            # Check for parked domains on this URL too
                            is_parked = any(ind in page_lower for ind in self.PARKED_INDICATORS)
                            if is_parked:
                                return {
                                    "status": "NOT_FOUND",
                                    "url": found_url,
                                    "detail": f"Parked/placeholder page. Not genuine. Title: '{page_title}'",
                                }

                            if entity_lower in page_lower:
                                return {
                                    "status": "FOUND",
                                    "url": found_url,
                                    "detail": f"VERIFIED — Entity name confirmed on page. Title: '{page_title}'",
                                }
                            else:
                                return {
                                    "status": "NOT_FOUND",
                                    "url": found_url,
                                    "detail": f"Page found but entity name NOT on page. Could not verify. Title: '{page_title}'",
                                }
                        else:
                            return {
                                "status": "NOT_FOUND",
                                "url": found_url,
                                "detail": f"URL found but page returned HTTP {page_resp.status_code}. Could not verify.",
                            }
                    except Exception:
                        return {
                            "status": "NOT_FOUND",
                            "url": found_url,
                            "detail": f"URL found on {site} but page could not be loaded. Could not verify.",
                        }

            return {
                "status": "NOT_FOUND",
                "url": "N/A",
                "detail": f"Entity not found on {site} — not registered or no public profile",
            }
        except Exception as exc:
            return {
                "status": "NOT_FOUND",
                "url": "N/A",
                "detail": f"Search failed: {str(exc)[:60]}",
            }

    def _check_sec_edgar(self, entity: str, headers: dict) -> dict:
        """Check SEC EDGAR for company filings."""
        try:
            url = f"https://efts.sec.gov/LATEST/search-index?q=%22{urllib.parse.quote_plus(entity)}%22"
            resp = self._session.get(url, headers={
                "User-Agent": "OSINT-Tool research@example.com",
                "Accept": "application/json",
            }, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                total = data.get("hits", {}).get("total", {}).get("value", 0)
                if total > 0:
                    return {
                        "status": "FOUND",
                        "url": f"https://www.sec.gov/cgi-bin/browse-edgar?company={urllib.parse.quote_plus(entity)}&CIK=&type=&dateb=&owner=include&count=10&search_text=&action=getcompany",
                        "detail": f"Found {total} SEC filing(s)",
                    }
            return {
                "status": "NOT_FOUND",
                "url": "N/A",
                "detail": "No SEC filings found — company may not be US-listed",
            }
        except Exception:
            return {"status": "NOT_FOUND", "url": "N/A", "detail": "SEC EDGAR search failed"}

    def _check_companies_house(self, entity: str, headers: dict) -> dict:
        """Check UK Companies House API (free, no key needed)."""
        try:
            url = f"https://api.company-information.service.gov.uk/search/companies?q={urllib.parse.quote_plus(entity)}"
            resp = self._session.get(url, headers={
                "User-Agent": "OSINT-Tool/1.0",
                "Accept": "application/json",
            }, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                if items:
                    top = items[0]
                    return {
                        "status": "FOUND",
                        "url": f"https://find-and-update.company-information.service.gov.uk{top.get('links', {}).get('self', '')}",
                        "detail": f"{top.get('title', 'N/A')} — Status: {top.get('company_status', 'N/A')}",
                    }
            return {
                "status": "NOT_FOUND",
                "url": "N/A",
                "detail": "No UK Companies House registration found",
            }
        except Exception:
            return {"status": "NOT_FOUND", "url": "N/A", "detail": "Companies House search failed"}

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _guess_tickers(entity: str) -> list:
        """Generate likely ticker symbols from entity name."""
        clean = re.sub(r'[^a-zA-Z0-9\s]', '', entity).strip()
        words = clean.upper().split()

        candidates = []
        # Try the entity name directly (e.g. "INFY", "TCS")
        if len(words) == 1 and len(words[0]) <= 5:
            candidates.append(words[0])

        # Try common Indian exchange suffixes
        if len(words) == 1:
            candidates.append(f"{words[0]}.NS")  # NSE
            candidates.append(f"{words[0]}.BO")  # BSE

        # Try acronym
        if len(words) > 1:
            acronym = "".join(w[0] for w in words)
            candidates.append(acronym)
            candidates.append(f"{acronym}.NS")

        return candidates[:6]  # Limit attempts

    @staticmethod
    def _fmt_number(n) -> str:
        """Format large numbers for readability."""
        if n is None:
            return "N/A"
        try:
            n = float(n)
            if abs(n) >= 1e12:
                return f"${n/1e12:.2f}T"
            if abs(n) >= 1e9:
                return f"${n/1e9:.2f}B"
            if abs(n) >= 1e6:
                return f"${n/1e6:.2f}M"
            if abs(n) >= 1e3:
                return f"${n/1e3:.1f}K"
            return f"${n:,.0f}"
        except (ValueError, TypeError):
            return str(n)

    @staticmethod
    def _financial_risk_tags(info: dict) -> list:
        tags = []
        margin = info.get("profitMargins")
        if margin is not None and margin < 0:
            tags.append("negative_profit")
        debt_eq = info.get("debtToEquity")
        if debt_eq is not None and debt_eq > 200:
            tags.append("high_debt")
        return tags

    @staticmethod
    def _discussion_risk_tags(text: str) -> list:
        tags = []
        negative_kw = [
            "scam", "fraud", "lawsuit", "layoff", "fired",
            "toxic", "avoid", "warning", "complaint", "worst",
            "bankrupt", "investigation", "hack", "breach", "leak",
        ]
        lowered = text.lower()
        for kw in negative_kw:
            if kw in lowered:
                tags.append("news_negative")
                break
        return tags
