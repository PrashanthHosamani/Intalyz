"""
main.py
OSINT Tool — CLI Entrypoint.

Usage:
    python main.py --entity "Travis Haasch" --type individual
    python main.py --entity "AIGeeks" --type company
    python main.py --entity "AIGeeks" --type company --adapters whois,github,contextual
"""

import logging
import sys
import os
import json
from typing import Optional

import click

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("osint")


@click.command()
@click.option(
    "--entity", "-e", required=True,
    help="Target entity name (company or individual)."
)
@click.option(
    "--type", "-t", "entity_type",
    type=click.Choice(["company", "individual"], case_sensitive=False),
    default="company", show_default=True,
    help="Type of entity being investigated."
)
@click.option(
    "--adapters", "-a", default="all",
    help="Comma-separated adapter names to run, or 'all'. "
         "Options: google_dork, whois_dns, github, contextual"
)
@click.option(
    "--output-dir", "-o", default=None,
    help="Override output directory for the report."
)
@click.option(
    "--save-json", is_flag=True, default=False,
    help="Also save raw findings as JSON alongside the PDF."
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False,
    help="Enable DEBUG logging."
)
def main(
    entity:      str,
    entity_type: str,
    adapters:    str,
    output_dir:  Optional[str],
    save_json:   bool,
    verbose:     bool,
):
    """
    \b
    ╔══════════════════════════════════════╗
    ║   OSINT Investigation Tool v1.0     ║
    ║   Automated Entity Discovery        ║
    ╚══════════════════════════════════════╝
    """

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if output_dir:
        from config import settings as cfg
        cfg.OUTPUT_DIR = output_dir
        os.makedirs(output_dir, exist_ok=True)

    from config import settings

    click.echo(click.style("\n🔍 OSINT Tool v1.0", fg="cyan", bold=True))
    click.echo(f"   Target : {entity}")
    click.echo(f"   Type   : {entity_type}")
    click.echo(f"   Output : {settings.OUTPUT_DIR}\n")

    # ── Load adapters ─────────────────────────────────────────────────────────
    available_adapters = _load_adapters(adapters)
    click.echo(f"   Adapters: {', '.join(a.ADAPTER_NAME for a in available_adapters)}\n")

    # ── Run orchestrator ──────────────────────────────────────────────────────
    from core.orchestrator import Orchestrator
    orchestrator = Orchestrator(available_adapters)

    click.echo(click.style("Phase I  — Data Acquisition…", fg="yellow"))
    raw = orchestrator.run(entity, entity_type)

    # ── Entity resolution ─────────────────────────────────────────────────────
    click.echo(click.style("Phase II — Analysis & Entity Resolution…", fg="yellow"))
    from analysis.entity_resolver import EntityResolver
    resolver = EntityResolver(entity, entity_type)
    resolved = resolver.resolve(raw["results"])

    # ── Build entity relationship graph ────────────────────────────────────────
    click.echo(click.style("Phase II.5 — Mapping Entity Relationships…", fg="yellow"))
    from analysis.entity_relationship_mapper import EntityRelationshipMapper
    relationship_mapper = EntityRelationshipMapper(entity, entity_type)
    relationships = relationship_mapper.build_graph(resolved["confirmed"])
    click.echo(relationship_mapper.get_summary())

    # ── Risk scoring ──────────────────────────────────────────────────────────
    from analysis.risk_scorer import RiskScorer
    risk = RiskScorer().score(resolved)

    click.echo(
        click.style(
            f"         Risk Score: {risk['risk_score']}/100 — {risk['severity']}",
            fg="red" if risk["risk_score"] >= 60 else "green",
            bold=True,
        )
    )

    # ── Generate PDF report ───────────────────────────────────────────────────
    click.echo(click.style("Phase III — Generating PDF Report…", fg="yellow"))
    from reporting.pdf_reporter import PDFReporter
    reporter = PDFReporter()
    pdf_path = reporter.generate(entity, resolved, risk, raw, relationships)

    click.echo(click.style(f"\n✅ Report saved: {pdf_path}", fg="green", bold=True))

    # ── Optional JSON dump ────────────────────────────────────────────────────
    if save_json:
        json_path = pdf_path.replace(".pdf", ".json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(
                {"entity": entity, "resolved": resolved, "risk": risk, "raw": raw},
                f, indent=2, default=str,
            )
        click.echo(click.style(f"   JSON dump: {json_path}", fg="cyan"))

    # ── Summary banner ────────────────────────────────────────────────────────
    click.echo("\n" + click.style("─" * 50, fg="bright_black"))
    click.echo(f"  Confirmed findings : {len(resolved['confirmed'])}")
    click.echo(f"  False positives    : {len(resolved['false_positives'])}")
    click.echo(f"  Duplicates removed : {resolved['dedup_count']}")
    click.echo(f"  Risk               : {risk['risk_score']}/100 ({risk['severity']})")
    click.echo(click.style("─" * 50, fg="bright_black") + "\n")


def _load_adapters(adapter_filter: str):
    """Import and instantiate adapters based on filter string."""
    from adapters.google_dork_adapter import GoogleDorkAdapter
    from adapters.whois_dns_adapter   import WhoisDnsAdapter
    from adapters.github_adapter      import GitHubAdapter
    from adapters.contextual_adapter  import ContextualAdapter
    from adapters.otx_adapter         import OtxAdapter
    from adapters.company_intel_adapter import CompanyIntelAdapter
    from adapters.person_verification_adapter import PersonVerificationAdapter
    from adapters.website_verification_adapter import WebsiteVerificationAdapter
    from adapters.company_discovery_adapter import CompanyDiscoveryAdapter

    ALL = {
        "google_dork":     GoogleDorkAdapter,
        "whois_dns":       WhoisDnsAdapter,
        "github":          GitHubAdapter,
        "contextual":      ContextualAdapter,
        "otx":             OtxAdapter,
        "company_intel":   CompanyIntelAdapter,
        "person_verification": PersonVerificationAdapter,
        "website_verification": WebsiteVerificationAdapter,
        "company_discovery": CompanyDiscoveryAdapter,
    }

    if adapter_filter.strip().lower() == "all":
        selected = list(ALL.keys())
    else:
        selected = [a.strip() for a in adapter_filter.split(",")]

    instances = []
    for name in selected:
        if name in ALL:
            try:
                instances.append(ALL[name]())
            except Exception as exc:
                logger.warning("Could not initialise adapter %s: %s", name, exc)
        else:
            logger.warning("Unknown adapter: %s (skipped)", name)

    return instances


if __name__ == "__main__":
    main()
