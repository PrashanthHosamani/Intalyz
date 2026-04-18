#!/usr/bin/env python
"""Set admin password to admin123 for testing"""
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'osint_project.settings')
django.setup()

from accounts.models import CustomUser

admin_user = CustomUser.objects.get(username='admin')
admin_user.set_password('admin123')
admin_user.save()
print("✓ Admin password set to: admin123")
print("✓ Username: admin")
print("✓ Email: admin@osint.local")
