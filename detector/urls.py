from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('api/scan/', views.scan_url_api, name='scan_api'),
    path('api/report-feedback/', views.report_feedback, name='report_feedback'),
]