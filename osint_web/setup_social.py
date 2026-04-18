import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'osint_project.settings')
django.setup()

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site

app, created = SocialApp.objects.get_or_create(
    provider='google',
    name='Google Auth',
    client_id=os.environ.get('GOOGLE_CLIENT_ID', '').strip(),
)
app.secret = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip()
app.save()

site = Site.objects.get(id=1)
app.sites.add(site)
print("SocialApp created/updated in DB!")
