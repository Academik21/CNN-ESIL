from django.urls import include, path
from . import views


urlpatterns = [
    path('', views.index, name='index'),
    path('detect/', views.simple_upload, name='simple_upload'),
    path('main/', views.main, name = 'main'),
    path('scan/', views.scan, name = 'scan'),
    path('registr/', views.registr),
    path('history/', views.history, name = 'history') 
]