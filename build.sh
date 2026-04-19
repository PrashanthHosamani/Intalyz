#!/usr/bin/env bash
# exit on error
set -o errexit

echo "📦 Installing Requirements..."
pip install -r requirements.txt

echo "⚙️  Collecting Static Files..."
cd osint_web
python manage.py collectstatic --no-input

echo "🗄️  Running Database Migrations..."
python manage.py migrate

echo "✅ Build Complete!"
