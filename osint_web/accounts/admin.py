"""accounts/admin.py - Admin configuration for CustomUser"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """Admin interface for CustomUser model."""
    
    model = CustomUser
    
    # Fields shown in list view
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_verified', 'is_staff', 'created_at')
    list_filter = ('is_staff', 'is_superuser', 'is_verified', 'created_at')
    list_editable = ('is_verified',)
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-created_at',)
    
    # Fields shown in detail view
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Account Information', {
            'fields': ('phone_number', 'bio', 'profile_picture', 'is_verified')
        }),
        ('Google OAuth', {
            'fields': ('google_id', 'google_picture_url'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at', 'google_id', 'google_picture_url')
    
    def get_fieldsets(self, request, obj=None):
        """Customize fieldsets based on user permissions."""
        fieldsets = super().get_fieldsets(request, obj)
        if not request.user.is_superuser:
            # Remove sensitive fields from non-superusers
            return [(name, opts) for name, opts in fieldsets if name != 'Permissions']
        return fieldsets
