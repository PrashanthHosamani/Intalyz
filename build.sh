#!/usr/bin/env bash
# exit on error
set -o errexit

echo "📦 Installing Requirements..."
pip install -r requirements.txt

echo "⚙️  Collecting Static Files..."
cd osint_web
python manage.py collectstatic --no-input

# NOTE: migrations are NOT run here. Render's build environment cannot reach the
# database (the internal hostname only resolves at runtime), so `migrate` belongs
# in the start command instead — see startCommand in render.yaml.

echo "✅ Build Complete!"
