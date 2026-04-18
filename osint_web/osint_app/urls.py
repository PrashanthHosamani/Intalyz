"""osint_app/urls.py"""
from django.urls import path
from . import views

urlpatterns = [
    path('',                        views.index,                name='index'),
    path('investigate/',            views.submit_investigation, name='submit_investigation'),
    path('status/<uuid:job_id>/',   views.job_status,           name='job_status'),
    path('download/<uuid:job_id>/', views.download_report,      name='download_report'),
]
