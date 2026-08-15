from django.db import migrations


def remove_google_socialapps(apps, schema_editor):
    """
    Google OAuth is configured in settings.py via SOCIALACCOUNT_PROVIDERS
    (reading GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET from the environment).

    A Google SocialApp row also existed in the database (created previously by
    setup_social.py). django-allauth then found the app defined in BOTH places
    and raised MultipleObjectsReturned, causing a 500 on /accounts/google/login/.

    This migration deletes any Google SocialApp rows so the settings.py config is
    the single source of truth. It runs automatically on every deploy via
    `python manage.py migrate` in build.sh. Safe no-op if no rows exist.
    """
    SocialApp = apps.get_model('socialaccount', 'SocialApp')
    SocialApp.objects.filter(provider='google').delete()


def noop_reverse(apps, schema_editor):
    # Nothing to restore; the app is defined in settings.py.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
        ('socialaccount', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(remove_google_socialapps, noop_reverse),
    ]
