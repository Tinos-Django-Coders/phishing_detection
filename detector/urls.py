from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin-dashboard/login/', views.admin_dashboard_login, name='admin_dashboard_login'),
    path('admin-dashboard/logout/', views.admin_dashboard_logout, name='admin_dashboard_logout'),
    path('login/', views.user_login, name='user_login'),
    path('logout/', views.user_logout, name='user_logout'),
    path('signup/', views.user_signup, name='user_signup'),
    path('privacy-policy/', views.legal_page, {'page': 'privacy-policy'}, name='privacy_policy'),
    path('disclosures/', views.legal_page, {'page': 'disclosures'}, name='disclosures'),
    path('api/scan/', views.scan_url_api, name='scan_api'),
    path('api/report-feedback/', views.report_feedback, name='report_feedback'),
]
