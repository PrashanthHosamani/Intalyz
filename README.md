# Intalyz.io — Active OSINT Corporate Due Diligence Platform

Intalyz.io is an automated, high-precision open-source intelligence (OSINT) and corporate due diligence engine. It transforms raw internet data into highly structured, professional PDF intelligence reports. 

Unlike traditional passive OSINT tools, Intalyz.io actively probes internet records, bypasses anti-bot systems, and evaluates companies across five distinct risk dimensions to generate actionable insights and a normalized composite risk score.

## 🚀 Key Features

### 1. Active Entity Verification Engine
Bypasses the "static link" problem by programmatically visiting and verifying entity existence across global platforms:
* **Legal & Tax Registrations:** India (MCA, GST), US (SEC EDGAR), UK (Companies House).
* **Corporate Profiles:** Direct URL verification for LinkedIn, Crunchbase, Glassdoor, and Twitter/X.
* **Parked Domain Detection:** Actively parses website HTML and titles to distinguish between legitimate corporate websites and GoDaddy/placeholder domains.
* **Smart Index Verification:** Utilizes Google Dorking to bypass CAPTCHAs and 403 firewalls on heavily protected government portals (e.g., `mca.gov.in`).

### 2. Multi-Dimensional Risk Scoring
Traditional tools often issue critical risk alerts simply because an entity lacks a Twitter account. Intalyz.io uses a highly weighted, 5-dimension risk model:
* **Cyber Risk (30%)**: Past breaches, exposed credentials, DNS hygiene.
* **Reputation (25%)**: Negative news sentiment, regulatory warnings.
* **Digital Footprint (15%)**: Ghost company detection, parked domains.
* **Financial (15%)**: High debt-to-equity, abnormal revenue drops.
* **Verification Gap (15%)**: Lack of legal registration or verifiable physical presence.
*(Note: Empty or harmless dimensions are explicitly excluded from penalizing the final score).*

### 3. Public & Private Financial Intelligence
* **Public Entities:** Uses `yfinance` to automatically pull Balance Sheets, P&L, Market Cap, and Enterprise Value.
* **Private Entities:** Features a fallback scraping engine that extracts exact revenue and net profit figures (e.g., "₹8,847 Crore") from recent financial news articles, while linking out to Tofler and Zauba Corp for deep-dives.

### 4. Corporate-Ready PDF Reporting
Generates visually stunning, perfectly wrapped PDF reports using `ReportLab`, complete with:
* Executive summaries.
* Multi-dimensional Risk Dashboards.
* A live Verification Checklist (✅ VERIFIED / ❌ NOT FOUND).
* Interactive data links and proof URLs.

## 🛠️ Technology Stack

* **Core Engine:** Python 3.14
* **Web App UI:** Django 6.0
* **Authentication:** Google OAuth 2.0 (`django-allauth`)
* **Reporting:** ReportLab (PDF Generation)
* **Financials:** `yfinance`
* **Scraping & Requests:** `requests`, custom User-Agent rotation, RegEx HTML parsing.

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/intalyz-osint.git
   cd intalyz-osint
   ```

2. **Set up a virtual environment:**
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables:**
   You will need two `.env` files. 
   * `/osint_tool/config/.env` for OSINT API Keys (GitHub, NewsAPI, AlienVault OTX).
   * `/osint_web/.env` for Django keys (Google Client ID & Secret).
   *(Use the provided sample `.env` templates).*

5. **Run the Django Web Server:**
   ```bash
   cd osint_web
   python manage.py makemigrations
   python manage.py migrate
   python manage.py runserver
   ```

## 🧠 Architecture Overview

The system is split into two primary layers:
1. **`osint_tool/` (The Engine):** Contains the `RiskScorer` and specialized adapters (`CompanyIntelAdapter`, `GoogleDorkAdapter`, `ContextualAdapter`) that handle the heavy lifting, rate limiting, and data aggregation.
2. **`osint_web/` (The Frontend):** A Django application that handles user authentication, receives investigation requests, triggers the OSINT engine, and serves the resulting PDF reports.

## 🛡️ Legal & Compliance
This tool is designed strictly for legal due diligence, risk assessment, and authorized OSINT investigations. It utilizes publicly available data (OSINT) and complies with standard rate-limiting practices. Do not use this tool for unauthorized scraping or malicious reconnaissance.
