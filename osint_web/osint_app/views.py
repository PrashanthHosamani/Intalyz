"""osint_app/views.py"""
import os
import sys
import threading
import json
import logging
from datetime import datetime, timezone

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, FileResponse, Http404, HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.utils import timezone as tz

from .models import InvestigationJob

logger = logging.getLogger(__name__)

# Add osint_tool to path
sys.path.insert(0, settings.OSINT_TOOL_PATH)


def index(request):
    """Main page — render the investigation form. Publicly accessible."""
    if request.user.is_authenticated:
        recent_jobs = InvestigationJob.objects.filter(
            user=request.user,
            status__in=['completed', 'running', 'pending']
        )[:5]
        total_jobs = InvestigationJob.objects.filter(user=request.user).count()
        completed_jobs = InvestigationJob.objects.filter(user=request.user, status='completed').count()
    else:
        recent_jobs = []
        total_jobs = 0
        completed_jobs = 0

    context = {
        'recent_jobs': recent_jobs,
        'total_jobs': total_jobs,
        'completed_jobs': completed_jobs,
    }
    return render(request, 'osint_app/index.html', context)


@login_required(login_url='accounts:signin')
@csrf_exempt
@require_http_methods(["POST"])
def submit_investigation(request):
    """
    Accept form submission, create a job, kick off background thread.
    Returns JSON with job ID for polling.
    """
    try:
        data = json.loads(request.body)
    except Exception:
        data = request.POST

    entity_name = data.get('entity_name', '').strip()
    entity_type = data.get('entity_type', 'company').strip()
    aliases     = data.get('aliases', '').strip()
    adapters    = data.get('adapters', 'google_dork,whois_dns,github,contextual').strip()

    if not entity_name:
        return JsonResponse({'error': 'Entity name is required.'}, status=400)

    # Create job record with current user
    job = InvestigationJob.objects.create(
        user=request.user,
        entity_name=entity_name,
        entity_type=entity_type,
        aliases=aliases,
        adapters=adapters,
        status='pending',
    )

    # Run pipeline in background thread
    thread = threading.Thread(target=_run_pipeline, args=(str(job.id),), daemon=True)
    thread.start()

    return JsonResponse({
        'job_id':      str(job.id),
        'entity_name': entity_name,
        'status':      'pending',
        'message':     f'Investigation started for "{entity_name}"',
    })


@login_required(login_url='accounts:signin')
def job_status(request, job_id):
    """Poll endpoint — returns current job status + result info."""
    job = get_object_or_404(InvestigationJob, id=job_id, user=request.user)
    data = {
        'job_id':        str(job.id),
        'entity_name':   job.entity_name,
        'entity_type':   job.entity_type,
        'status':        job.status,
        'risk_score':    job.risk_score,
        'severity':      job.severity,
        'findings_count':job.findings_count,
        'error_message': job.error_message,
        'created_at':    job.created_at.isoformat(),
        'completed_at':  job.completed_at.isoformat() if job.completed_at else None,
        'download_url':  f'/download/{job.id}/' if job.status == 'completed' else None,
    }
    return JsonResponse(data)


@login_required(login_url='accounts:signin')
def download_report(request, job_id):
    """Serve the local PDF report file."""
    job = get_object_or_404(InvestigationJob, id=job_id, user=request.user)
    if job.status != 'completed' or not job.report_file:
        return HttpResponse("Report not ready or missing.", status=404)

    # Serve the file directly using FileResponse
    try:
        response = FileResponse(job.report_file.open('rb'), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="osint_report_{job.entity_name}.pdf"'
        return response
    except Exception as e:
        logger.error(f"Error serving report: {e}")
        return HttpResponse("Error retrieving report file.", status=500)


def privacy_policy(request):
    """Serve the Privacy Policy page."""
    return render(request, 'osint_app/privacy_policy.html')


# ── Background pipeline runner ────────────────────────────────────────────────

def _run_pipeline(job_id: str):
    """
    Runs the full OSINT pipeline in a background thread.
    Updates the InvestigationJob record with results.
    """
    from osint_app.models import InvestigationJob as Job

    job = Job.objects.get(id=job_id)
    job.status = 'running'
    job.save(update_fields=['status'])

    try:
        # Import OSINT modules
        from core.orchestrator import Orchestrator
        from analysis.entity_resolver import EntityResolver
        from analysis.entity_relationship_mapper import EntityRelationshipMapper
        from analysis.entity_verification import EntityVerifier
        from analysis.risk_scorer import RiskScorer
        from reporting.pdf_reporter import PDFReporter
        from config import settings as osint_cfg

        # Point output to Django media folder
        os.makedirs(settings.OSINT_OUTPUT_DIR, exist_ok=True)
        osint_cfg.OUTPUT_DIR = settings.OSINT_OUTPUT_DIR

        # Phase 0 — Entity Verification (NEW)
        # Verify entity exists before running expensive adapters
        logger.info("🔍 Starting entity verification for: %s (%s)", 
                   job.entity_name, job.entity_type)
        
        verifier = EntityVerifier()
        is_verified, verification_confidence, verification_details = verifier.verify(
            job.entity_name, 
            job.entity_type
        )
        
        logger.info("✓ Entity verification complete: %s (confidence: %.0f%%)", 
                   "PASS" if is_verified else "FAIL", verification_confidence)
        
        # If entity fails verification, skip low-value adapters
        skip_adapters = set()
        if not is_verified or verification_confidence < 40:
            logger.warning("⚠ Entity verification failed - skipping speculative adapters")
            skip_adapters = {
                'contextual',  # Highly speculative
                'company_intel',  # Often returns false positives
                'company_discovery',  # Can't discover company if entity not verified
            }

        # Get selected adapters from job record
        selected_adapters = [a.strip() for a in job.adapters.split(',') if a.strip()]
        
        # Always include intelligent adapters for better analysis if entity is verified
        if selected_adapters and is_verified:
            # Add the new intelligent adapters if not already present
            intelligent_adapters = ['person_verification', 'website_verification']
            
            # For individual searches, always add company discovery
            if job.entity_type == 'individual':
                intelligent_adapters.append('company_discovery')
            
            for adapter in intelligent_adapters:
                if adapter not in selected_adapters and adapter not in skip_adapters:
                    selected_adapters.append(adapter)
        
        # Remove skipped adapters
        selected_adapters = [a for a in selected_adapters if a not in skip_adapters]
        
        logger.info("Loading adapters: %s (skipped: %s)", selected_adapters, skip_adapters)
        
        # Load adapters
        adapters = _load_adapters(selected_adapters)

        # Phase I — Data Acquisition
        orchestrator = Orchestrator(adapters)
        raw = orchestrator.run(job.entity_name, job.entity_type)

        # Phase II — Analysis & Entity Resolution
        alias_list = [a.strip() for a in job.aliases.split(',') if a.strip()]
        resolver = EntityResolver(job.entity_name, job.entity_type, aliases=alias_list)
        resolved = resolver.resolve(raw['results'])
        
        # Add verification info to resolved data
        resolved['entity_verified'] = is_verified
        resolved['verification_confidence'] = verification_confidence
        resolved['verification_details'] = verification_details

        # Phase II.5 — Build Entity Relationship Graph
        relationship_mapper = EntityRelationshipMapper(job.entity_name, job.entity_type)
        relationships = relationship_mapper.build_graph(resolved['confirmed'])

        # Phase III — Risk Scoring
        risk = RiskScorer().score(resolved)

        # Phase IV — PDF Report with Relationships
        reporter = PDFReporter()
        pdf_path = reporter.generate(job.entity_name, resolved, risk, raw, relationships)

        # Update job record and save report
        from django.core.files import File
        with open(pdf_path, 'rb') as f:
            job.status         = 'completed'
            job.risk_score     = risk['risk_score']
            job.severity       = risk['severity']
            job.findings_count = len(resolved['confirmed'])
            job.completed_at   = tz.now()
            job.verification_status = 'verified' if is_verified else 'unverified'
            
            # Save the file locally
            slug = job.entity_name.lower().replace(' ', '_')
            filename = f"osint_report_{slug}_{job.id.hex[:8]}.pdf"
            job.report_file.save(filename, File(f), save=True)

    except Exception as exc:
        import traceback
        job.status        = 'failed'
        job.error_message = str(exc) + '\n' + traceback.format_exc()
        job.completed_at  = tz.now()
        job.save()


def _load_adapters(adapter_names=None):
    """
    Load adapters. If adapter_names is provided, only load those adapters.
    Otherwise, load all adapters.
    """
    adapter_map = {}
    
    from adapters.google_dork_adapter import GoogleDorkAdapter
    from adapters.whois_dns_adapter   import WhoisDnsAdapter
    from adapters.github_adapter      import GitHubAdapter
    from adapters.contextual_adapter  import ContextualAdapter
    from adapters.company_intel_adapter import CompanyIntelAdapter
    from adapters.person_verification_adapter import PersonVerificationAdapter
    from adapters.website_verification_adapter import WebsiteVerificationAdapter
    from adapters.company_discovery_adapter import CompanyDiscoveryAdapter
    
    adapter_map['google_dork']        = GoogleDorkAdapter()
    adapter_map['whois_dns']          = WhoisDnsAdapter()
    adapter_map['github']             = GitHubAdapter()
    adapter_map['contextual']         = ContextualAdapter()
    adapter_map['company_intel']      = CompanyIntelAdapter()
    adapter_map['person_verification'] = PersonVerificationAdapter()
    adapter_map['website_verification'] = WebsiteVerificationAdapter()
    adapter_map['company_discovery'] = CompanyDiscoveryAdapter()
    
    if adapter_names:
        return [adapter_map[name] for name in adapter_names if name in adapter_map]
    
    return list(adapter_map.values())
