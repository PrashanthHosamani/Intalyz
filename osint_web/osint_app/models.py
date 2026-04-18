"""osint_app/models.py"""
from django.db import models
from django.conf import settings
import uuid


class InvestigationJob(models.Model):
    """Tracks each OSINT investigation request."""

    STATUS_CHOICES = [
        ('pending',    'Pending'),
        ('running',    'Running'),
        ('completed',  'Completed'),
        ('failed',     'Failed'),
    ]

    ENTITY_TYPE_CHOICES = [
        ('company',    'Company'),
        ('individual', 'Individual'),
    ]

    id            = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user          = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, help_text="User who created this investigation")
    entity_name   = models.CharField(max_length=255)
    entity_type   = models.CharField(max_length=20, choices=ENTITY_TYPE_CHOICES, default='company')
    aliases       = models.CharField(max_length=500, blank=True, help_text="Comma-separated aliases")
    adapters      = models.CharField(max_length=255, blank=True, default='google_dork,whois_dns,github,contextual', help_text="Comma-separated adapter names")
    status        = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    risk_score    = models.IntegerField(null=True, blank=True)
    severity      = models.CharField(max_length=20, blank=True)
    findings_count= models.IntegerField(default=0)
    report_file   = models.FileField(upload_to='reports/', null=True, blank=True)
    error_message = models.TextField(blank=True)
    created_at    = models.DateTimeField(auto_now_add=True)
    completed_at  = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Investigation Job'
        verbose_name_plural = 'Investigation Jobs'

    def __str__(self):
        return f"{self.entity_name} ({self.status}) - {self.user.username}"
