from django.urls import path

from user_model import views
from user_login import views as login_views
from user_info import views as info_views

urlpatterns = [
    path('register', view = views.register, name = 'register'),
    path('login', view = login_views.login, name = 'login'),
    path('info', view = info_views.info, name = 'info'),
    path('me', view = info_views.update_me, name = 'update-me'),
]
