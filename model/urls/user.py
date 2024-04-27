from django.urls import path

from model import views

urlpatterns = [
    path('register', view = views.register, name = 'register'),
    path('login', view = views.login, name = 'login'),
    path('info', view = views.info, name = 'info'),
    path('me', view = views.update_me, name = 'update-me'),
]
