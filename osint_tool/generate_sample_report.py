"""
generate_sample_report.py
Generates the submission sample report for "Travis Haasch" — CEO of AIGeeks.
Uses realistic mock findings to demonstrate the full pipeline without live API keys.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timezone
from analysis.entity_resolver import EntityResolver
from analysis.risk_scorer import RiskScorer
from reporting.pdf_reporter import PDFReporter
from config import settings

# ── Override output dir ───────────────────────────────────────────────────────
settings.OUTPUT_DIR = "./output"
os.makedirs(settings.OUTPUT_DIR, exist_ok=True)

# ── Realistic mock adapter results ────────────────────────────────────────────
NOW = datetime.now(timezone.utc).isoformat()

MOCK_RESULTS = [
    # ── Social / Google Dork findings ─────────────────────────────────────────
    {
        "adapter":      "google_dork",
        "category":     "social",
        "retrieved_at": NOW,
        "record_count": 4,
        "errors":       [],
        "data": [
            {
                "title":           "Google Dork Result",
                "value":           {"query": '"Travis Haasch" site:linkedin.com', "url": "https://www.linkedin.com/in/travis-haasch"},
                "source_url":      "https://www.linkedin.com/in/travis-haasch",
                "retrieved_at":    NOW,
                "risk_tags":       [],
                "metadata":        {},
            },
            {
                "title":           "Google Dork Result",
                "value":           {"query": '"AIGeeks" site:crunchbase.com', "url": "https://www.crunchbase.com/organization/aigeeks"},
                "source_url":      "https://www.crunchbase.com/organization/aigeeks",
                "retrieved_at":    NOW,
                "risk_tags":       [],
                "metadata":        {},
            },
            {
                "title":           "Google Dork Result",
                "value":           {"query": '"AIGeeks" "data breach" OR "leaked"', "url": "https://pastebin.com/raw/aigeeks_exposure_2023"},
                "source_url":      "https://pastebin.com/raw/aigeeks_exposure_2023",
                "retrieved_at":    NOW,
                "risk_tags":       ["leaked_secret"],
                "metadata":        {},
            },
            {
                "title":           "Google Dork Result",
                "value":           {"query": '"Travis Haasch" site:github.com', "url": "https://github.com/travishaasch"},
                "source_url":      "https://github.com/travishaasch",
                "retrieved_at":    NOW,
                "risk_tags":       ["public_repo"],
                "metadata":        {},
            },
        ],
    },

    # ── Infrastructure / WHOIS + DNS ──────────────────────────────────────────
    {
        "adapter":      "whois_dns",
        "category":     "infrastructure",
        "retrieved_at": NOW,
        "record_count": 5,
        "errors":       [],
        "data": [
            {
                "title":        "WHOIS Record",
                "value":        {
                    "domain":       "aigeeks.com",
                    "registrar":    "Namecheap, Inc.",
                    "created":      "2021-03-14",
                    "expires":      "2026-03-14",
                    "updated":      "2024-03-01",
                    "name_servers": ["ns1.namecheap.com", "ns2.namecheap.com"],
                    "emails":       ["admin@aigeeks.com"],
                    "org":          "AIGeeks LLC",
                    "country":      "US",
                },
                "source_url":   "https://whois.domaintools.com/aigeeks.com",
                "retrieved_at": NOW,
                "risk_tags":    [],
                "metadata":     {},
            },
            {
                "title":        "DNS A Record",
                "value":        {"domain": "aigeeks.com", "type": "A", "records": ["104.21.42.87", "172.67.145.203"]},
                "source_url":   "https://dnschecker.org/#A/aigeeks.com",
                "retrieved_at": NOW,
                "risk_tags":    [],
                "metadata":     {},
            },
            {
                "title":        "DNS MX Record",
                "value":        {"domain": "aigeeks.com", "type": "MX", "records": ["10 mail.aigeeks.com"]},
                "source_url":   "https://dnschecker.org/#MX/aigeeks.com",
                "retrieved_at": NOW,
                "risk_tags":    [],
                "metadata":     {},
            },
            {
                "title":        "DNS TXT Record",
                "value":        {"domain": "aigeeks.com", "type": "TXT", "records": ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc123XYZ"]},
                "source_url":   "https://dnschecker.org/#TXT/aigeeks.com",
                "retrieved_at": NOW,
                "risk_tags":    [],
                "metadata":     {},
            },
            {
                "title":        "DNS NS Record",
                "value":        {"domain": "aigeeks.com", "type": "NS", "records": ["ns1.namecheap.com", "ns2.namecheap.com"]},
                "source_url":   "https://dnschecker.org/#NS/aigeeks.com",
                "retrieved_at": NOW,
                "risk_tags":    [],
                "metadata":     {},
            },
        ],
    },

    # ── Infrastructure / GitHub ───────────────────────────────────────────────
    {
        "adapter":      "github",
        "category":     "infrastructure",
        "retrieved_at": NOW,
        "record_count": 3,
        "errors":       [],
        "data": [
            {
                "title":        "GitHub Repository",
                "value":        {
                    "name":        "AIGeeks/aigeeks-platform",
                    "url":         "https://github.com/AIGeeks/aigeeks-platform",
                    "description": "Core AI platform powering the AIGeeks product suite",
                    "stars":       214,
                    "language":    "Python",
                    "created":     "2022-06-01",
                    "updated":     "2025-04-10",
                    "topics":      ["ai", "nlp", "openai", "llm"],
                    "is_fork":     False,
                },
                "source_url":   "https://github.com/AIGeeks/aigeeks-platform",
                "retrieved_at": NOW,
                "risk_tags":    ["public_repo"],
                "metadata":     {},
            },
            {
                "title":        "GitHub Repository",
                "value":        {
                    "name":        "AIGeeks/internal-config",
                    "url":         "https://github.com/AIGeeks/internal-config",
                    "description": "Internal deployment configs — do not distribute",
                    "stars":       2,
                    "language":    "YAML",
                    "created":     "2023-01-15",
                    "updated":     "2024-12-20",
                    "topics":      [],
                    "is_fork":     False,
                },
                "source_url":   "https://github.com/AIGeeks/internal-config",
                "retrieved_at": NOW,
                "risk_tags":    ["public_repo", "leaked_secret"],
                "metadata":     {},
            },
            {
                "title":        "GitHub Organisation",
                "value":        {
                    "login":        "AIGeeks",
                    "url":          "https://github.com/AIGeeks",
                    "name":         "AIGeeks",
                    "bio":          "Building the future of AI tooling",
                    "location":     "San Francisco, CA",
                    "email":        "dev@aigeeks.com",
                    "public_repos": 17,
                },
                "source_url":   "https://github.com/AIGeeks",
                "retrieved_at": NOW,
                "risk_tags":    ["public_repo"],
                "metadata":     {},
            },
        ],
    },

    # ── Regulatory / Contextual ───────────────────────────────────────────────
    {
        "adapter":      "contextual",
        "category":     "regulatory",
        "retrieved_at": NOW,
        "record_count": 5,
        "errors":       [],
        "data": [
            {
                "title":        "Data Breach Found (HIBP)",
                "value":        {
                    "name":         "AIGeeks2023Breach",
                    "domain":       "aigeeks.com",
                    "breach_date":  "2023-08-14",
                    "pwn_count":    4821,
                    "data_classes": ["Email addresses", "Passwords", "Names", "Phone numbers"],
                    "is_verified":  True,
                    "description":  "In August 2023, AIGeeks suffered a credential exposure affecting 4,821 user accounts. Email addresses, hashed passwords, and user metadata were found on a darkweb paste site.",
                },
                "source_url":   "https://haveibeenpwned.com/account/aigeeks.com",
                "retrieved_at": NOW,
                "risk_tags":    ["breach"],
                "metadata":     {},
            },
            {
                "title":        "OpenCorporates Registry Entry",
                "value":        {
                    "name":               "AIGEEKS LLC",
                    "company_number":     "0823456",
                    "jurisdiction":       "us_de",
                    "incorporation_date": "2021-03-10",
                    "dissolution_date":   None,
                    "status":             "Active",
                    "registered_address": "2711 Centerville Rd, Suite 400, Wilmington, DE 19808, US",
                    "opencorporates_url": "https://opencorporates.com/companies/us_de/0823456",
                },
                "source_url":   "https://opencorporates.com/companies/us_de/0823456",
                "retrieved_at": NOW,
                "risk_tags":    [],
                "metadata":     {},
            },
            {
                "title":        "News Mention",
                "value":        {
                    "headline":    "AIGeeks Raises $4.2M Seed Round to Scale AI Workflow Platform",
                    "source":      "TechCrunch",
                    "published":   "2024-02-18T09:00:00Z",
                    "description": "San Francisco-based AIGeeks announced a $4.2M seed round led by Gradient Ventures to expand its AI automation platform for SMBs.",
                    "url":         "https://techcrunch.com/2024/02/18/aigeeks-seed-round",
                    "author":      "Kirsten Korosec",
                },
                "source_url":   "https://techcrunch.com/2024/02/18/aigeeks-seed-round",
                "retrieved_at": NOW,
                "risk_tags":    [],
                "metadata":     {},
            },
            {
                "title":        "News Mention",
                "value":        {
                    "headline":    "AIGeeks Data Leak Investigation Underway After User Credentials Surface Online",
                    "source":      "The Register",
                    "published":   "2023-08-20T14:30:00Z",
                    "description": "Security researchers flagged a paste containing thousands of AIGeeks user records. The company issued a breach notification and launched an internal investigation.",
                    "url":         "https://www.theregister.com/2023/08/20/aigeeks-data-leak",
                    "author":      "Connor Jones",
                },
                "source_url":   "https://www.theregister.com/2023/08/20/aigeeks-data-leak",
                "retrieved_at": NOW,
                "risk_tags":    ["news_negative"],
                "metadata":     {},
            },
            {
                "title":        "News Mention",
                "value":        {
                    "headline":    "Travis Haasch Named to Forbes 30 Under 30 — Enterprise Technology",
                    "source":      "Forbes",
                    "published":   "2024-12-02T08:00:00Z",
                    "description": "Travis Haasch, CEO of AIGeeks, was recognised in the Forbes 30 Under 30 list for building AI workflow tooling adopted by over 1,200 SMBs globally.",
                    "url":         "https://www.forbes.com/30-under-30/2025/enterprise-technology/travis-haasch",
                    "author":      "Forbes Staff",
                },
                "source_url":   "https://www.forbes.com/30-under-30/2025/enterprise-technology/travis-haasch",
                "retrieved_at": NOW,
                "risk_tags":    [],
                "metadata":     {},
            },
        ],
    },
]

# ── Run pipeline ──────────────────────────────────────────────────────────────

def generate():
    entity      = "Travis Haasch"
    entity_type = "individual"

    print(f"\n🔍 Generating sample OSINT report for: {entity} (CEO of AIGeeks)")
    print("─" * 60)

    # Phase II — Entity Resolution
    print("Phase II — Running entity resolution…")
    resolver = EntityResolver(entity, entity_type, aliases=["AIGeeks", "aigeeks.com"])
    resolved = resolver.resolve(MOCK_RESULTS)
    print(f"  ✔ Confirmed: {len(resolved['confirmed'])}  |  False Positives: {len(resolved['false_positives'])}  |  Deduped: {resolved['dedup_count']}")

    # Phase II — Risk Scoring
    print("Phase II — Calculating risk score…")
    risk = RiskScorer().score(resolved)
    print(f"  ✔ Risk Score: {risk['risk_score']}/100  —  Severity: {risk['severity']}")

    # Phase III — PDF Report
    print("Phase III — Generating PDF report…")
    reporter = PDFReporter()
    raw_meta = {"entity": entity, "entity_type": entity_type, "errors": []}
    pdf_path = reporter.generate(entity, resolved, risk, raw_meta)

    print(f"\n✅ Report saved: {pdf_path}")
    print("─" * 60)
    return pdf_path


if __name__ == "__main__":
    generate()
