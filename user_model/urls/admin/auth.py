from django.urls import path

from user_login import views as login_views
from user_info import views as info_views

urlpatterns = [
    path('login', view = login_views.admin_login, name = 'admin-login'),
    path('info', view = info_views.info, name = 'info')
]
