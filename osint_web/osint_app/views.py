"""osint_app/views.py"""
import os
import sys
import threading
import json
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
    """Redirect to the Cloudinary URL for the PDF."""
    job = get_object_or_404(InvestigationJob, id=job_id, user=request.user)
    if job.status != 'completed' or not job.report_file:
        return HttpResponse("Report not ready.", status=404)

    # Instead of serving local file, redirect to Cloudinary URL
    return HttpResponseRedirect(job.report_file.url)


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
        from analysis.risk_scorer import RiskScorer
        from reporting.pdf_reporter import PDFReporter
        from config import settings as osint_cfg

        # Point output to Django media folder
        os.makedirs(settings.OSINT_OUTPUT_DIR, exist_ok=True)
        osint_cfg.OUTPUT_DIR = settings.OSINT_OUTPUT_DIR

        # Get selected adapters from job record
        selected_adapters = [a.strip() for a in job.adapters.split(',') if a.strip()]
        
        # Load adapters
        adapters = _load_adapters(selected_adapters)

        # Phase I — Data Acquisition
        orchestrator = Orchestrator(adapters)
        raw = orchestrator.run(job.entity_name, job.entity_type)

        # Phase II — Analysis
        alias_list = [a.strip() for a in job.aliases.split(',') if a.strip()]
        resolver = EntityResolver(job.entity_name, job.entity_type, aliases=alias_list)
        resolved = resolver.resolve(raw['results'])

        risk = RiskScorer().score(resolved)

        # Phase III — PDF Report
        reporter = PDFReporter()
        pdf_path = reporter.generate(job.entity_name, resolved, risk, raw)

        # Update job record and upload to Cloudinary
        from django.core.files import File
        with open(pdf_path, 'rb') as f:
            job.status         = 'completed'
            job.risk_score     = risk['risk_score']
            job.severity       = risk['severity']
            job.findings_count = len(resolved['confirmed'])
            job.completed_at   = tz.now()
            
            # Saving to the FileField triggers the Cloudinary upload
            slug = job.entity_name.lower().replace(' ', '_')
            job.report_file.save(f"osint_report_{slug}.pdf", File(f), save=True)

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
    
    adapter_map['google_dork']   = GoogleDorkAdapter()
    adapter_map['whois_dns']     = WhoisDnsAdapter()
    adapter_map['github']        = GitHubAdapter()
    adapter_map['contextual']    = ContextualAdapter()
    adapter_map['company_intel'] = CompanyIntelAdapter()
    
    if adapter_names:
        return [adapter_map[name] for name in adapter_names if name in adapter_map]
    
    return list(adapter_map.values())
