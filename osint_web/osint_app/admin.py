from django.contrib import admin
from .models import InvestigationJob


@admin.register(InvestigationJob)
class InvestigationJobAdmin(admin.ModelAdmin):
    list_display  = ['entity_name', 'user', 'entity_type', 'status', 'risk_score', 'severity', 'created_at']
    list_filter   = ['status', 'entity_type', 'severity', 'created_at', 'user']
    search_fields = ['entity_name', 'user__username', 'user__email']
    readonly_fields = ['id', 'created_at', 'completed_at']
    fieldsets = (
        ('Investigation Details', {
            'fields': ('id', 'user', 'entity_name', 'entity_type', 'aliases', 'adapters')
        }),
        ('Results', {
            'fields': ('status', 'risk_score', 'severity', 'findings_count', 'error_message', 'report_file')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'completed_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        """Restrict non-superusers to their own investigations."""
        qs = super().get_queryset(request)
        if not request.user.is_superuser:
            qs = qs.filter(user=request.user)
        return qs
