# OSINT Intelligence Platform — Web Application

A full-stack Django web application that wraps the OSINT tool with a professional dark-themed frontend. Users submit an entity name via the browser and receive a downloadable PDF intelligence report.

---

## Project Layout

```
osint_web/                      ← Django project root
├── manage.py
├── osint_project/              ← Django settings & URL routing
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
└── osint_app/                  ← Main Django application
    ├── models.py               ← InvestigationJob database model
    ├── views.py                ← Form submission, job polling, PDF download
    ├── urls.py                 ← URL routing
    ├── admin.py                ← Django admin panel
    ├── templates/osint_app/
    │   └── index.html          ← Main UI template
    └── static/osint_app/
        ├── css/main.css        ← Dark intelligence-themed styles
        └── js/main.js          ← Form handling + polling logic

osint_tool/                     ← Existing OSINT engine (separate folder)
    (same structure as before)
```

---

## Setup & Run

### 1. Install dependencies

```bash
# In the osint_web directory
pip install django djangorestframework django-cors-headers
pip install -r ../osint_tool/requirements.txt
```

### 2. Configure API keys

```bash
cp ../osint_tool/config/.env.example ../osint_tool/config/.env
# Edit .env with your API keys
```

### 3. Run migrations

```bash
cd osint_web
python manage.py migrate
```

### 4. Start the server

```bash
python manage.py runserver
```

### 5. Open in browser

```
http://localhost:8000
```

---

## How It Works

1. User fills in entity name + type on the web UI
2. Django creates an `InvestigationJob` record in SQLite
3. A background thread runs the full OSINT pipeline
4. Frontend polls `/status/<job_id>/` every 3 seconds
5. When complete, user clicks **Download PDF** → served from `/download/<job_id>/`

---

## Admin Panel

```
http://localhost:8000/admin/
```

Create a superuser first:
```bash
python manage.py createsuperuser
```
