import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'osint_project.settings')
django.setup()

from allauth.socialaccount.models import SocialApp

# Google is now configured entirely in settings.py via SOCIALACCOUNT_PROVIDERS
# (reading GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET from the environment).
#
# Previously this script ALSO created a Google SocialApp row in the database.
# Having both a settings-based app AND a database row makes django-allauth raise
# MultipleObjectsReturned, which caused a 500 on /accounts/google/login/.
#
# To keep a single source of truth, this script now removes any Google
# SocialApp rows from the database so only the settings.py config remains.
deleted, _ = SocialApp.objects.filter(provider='google').delete()
print(f"Removed {deleted} Google SocialApp row(s) from DB. "
      f"Google OAuth is now configured via settings.py only.")
