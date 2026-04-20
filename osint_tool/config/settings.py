"""
config/settings.py
Central configuration loader for the OSINT tool.
Loads settings from .env file with sensible defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
ENV_FILE = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=ENV_FILE)

# ──────────────────────────────────────────────────────────────────────────────
# 1. EXTERNAL API KEYS
# ──────────────────────────────────────────────────────────────────────────────

GITHUB_TOKEN         = os.getenv("GITHUB_TOKEN", "").strip()
NEWS_API_KEY         = os.getenv("NEWS_API_KEY", "").strip()
OTX_API_KEY          = os.getenv("OTX_API_KEY", "").strip()

# ──────────────────────────────────────────────────────────────────────────────
# 2. OPSEC & PROXY SETTINGS
# ──────────────────────────────────────────────────────────────────────────────

USE_PROXIES           = os.getenv("USE_PROXIES", "false").lower() == "true"
PROXY_LIST            = [p.strip() for p in os.getenv("PROXY_LIST", "").split(",") if p.strip()]
PROXY_ROTATION_INTERVAL = int(os.getenv("PROXY_ROTATION_INTERVAL", "60"))
RANDOMIZE_REQUESTS    = os.getenv("RANDOMIZE_REQUESTS", "true").lower() == "true"

# ──────────────────────────────────────────────────────────────────────────────
# 3. HTTP DEFAULTS & RATE LIMITING
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT    = int(os.getenv("DEFAULT_TIMEOUT", "15"))
DEFAULT_RATE_LIMIT = float(os.getenv("DEFAULT_RATE_LIMIT", "2.0"))
MAX_RETRIES        = int(os.getenv("MAX_RETRIES", "3"))

# Per-adapter rate limits (in seconds)
def _get_rate_limit(key: str, default: float) -> float:
    val = os.getenv(key, "").strip()
    return float(val) if val else default

ADAPTER_RATE_LIMITS = {
    "google_dork": _get_rate_limit("GOOGLE_DORK_RATE_LIMIT", 8.0),  # Increased to 8s to avoid Google 429 blocking
    "whois_dns":   _get_rate_limit("WHOIS_DNS_RATE_LIMIT", 1.0),
    "github":      _get_rate_limit("GITHUB_RATE_LIMIT", 2.0),
    "contextual":  _get_rate_limit("CONTEXTUAL_RATE_LIMIT", 3.0),
    "otx":         _get_rate_limit("OTX_RATE_LIMIT", 1.0),
    "company_intel": _get_rate_limit("COMPANY_INTEL_RATE_LIMIT", 2.0),
}

# ──────────────────────────────────────────────────────────────────────────────
# 4. OUTPUT & LOGGING
# ──────────────────────────────────────────────────────────────────────────────

# Use absolute path to avoid relative path confusion
BASE_DIR = Path(__file__).parent.parent.parent  # Root of project
_OUTPUT_DIR = os.getenv("OUTPUT_DIR", "")

if _OUTPUT_DIR and os.path.isabs(_OUTPUT_DIR):
    OUTPUT_DIR = _OUTPUT_DIR
else:
    # Fallback to absolute path in root/output
    OUTPUT_DIR = str(BASE_DIR / "output")

LOG_LEVEL      = os.getenv("LOG_LEVEL", "INFO").upper()
FILE_LOGGING   = os.getenv("FILE_LOGGING", "true").lower() == "true"
LOG_FILE       = os.path.join(OUTPUT_DIR, "osint_tool.log")

# ──────────────────────────────────────────────────────────────────────────────
# 5. ADAPTER-SPECIFIC LIMITS
# ──────────────────────────────────────────────────────────────────────────────

# GoogleDorkAdapter
GOOGLE_DORK_MAX_RESULTS_PER_QUERY = int(os.getenv("GOOGLE_DORK_MAX_RESULTS_PER_QUERY", "5"))

# GitHubAdapter
GITHUB_MAX_REPOS = int(os.getenv("GITHUB_MAX_REPOS", "10"))
GITHUB_MAX_ORGS  = int(os.getenv("GITHUB_MAX_ORGS", "3"))

# ContextualAdapter
CONTEXTUAL_MAX_NEWS_ARTICLES = int(os.getenv("CONTEXTUAL_MAX_NEWS_ARTICLES", "10"))
CONTEXTUAL_MAX_BREACHES      = int(os.getenv("CONTEXTUAL_MAX_BREACHES", "5"))

# WhoisDnsAdapter
WHOIS_DNS_MAX_DOMAINS = int(os.getenv("WHOIS_DNS_MAX_DOMAINS", "6"))

# ──────────────────────────────────────────────────────────────────────────────
# 6. ENTITY RESOLUTION & RISK SCORING
# ──────────────────────────────────────────────────────────────────────────────

CONFIDENCE_THRESHOLD = int(os.getenv("CONFIDENCE_THRESHOLD", "60"))
USE_NER_LINKING      = os.getenv("USE_NER_LINKING", "true").lower() == "true"

# Risk weights for scoring engine
# Maps risk_tag → weight (higher = more dangerous)
RISK_WEIGHTS = {
    "breach":          10,   # Data breach found in HIBP
    "exposed_port":     7,   # Exposed service port
    "leaked_secret":   10,   # Credentials/API keys leaked
    "dark_web_mention": 9,   # Mentioned on dark web
    "public_repo":      3,   # Public GitHub repo
    "whois_privacy":    2,   # Domain privacy enabled
    "news_negative":    5,   # Negative news mention
    "dns_anomaly":      4,   # Unusual DNS configuration
    "negative_profit":  6,   # Company reporting losses
    "high_debt":        5,   # High debt-to-equity ratio
}

# ──────────────────────────────────────────────────────────────────────────────
# 7. DJANGO WEB APP SETTINGS (osint_web)
# ──────────────────────────────────────────────────────────────────────────────

DJANGO_SECRET_KEY     = os.getenv("DJANGO_SECRET_KEY", "change-this-in-production")
DJANGO_ALLOWED_HOSTS  = [h.strip() for h in os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")]
DJANGO_DEBUG          = os.getenv("DEBUG", "false").lower() == "true"
DJANGO_DATABASE_URL   = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")
