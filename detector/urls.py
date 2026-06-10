from django.urls import path
from . import views

urlpatterns = [
    path('', views.check_url, name='check_url'),
]