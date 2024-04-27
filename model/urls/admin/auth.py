from django.urls import path

from model import views

urlpatterns = [
    path('login', view = views.admin_login, name = 'admin-login'),
    path('info', view = views.info, name = 'info')
]
