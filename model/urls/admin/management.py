from django.urls import path

from model import views

urlpatterns = [
    path('', view = views.get_admins, name = 'get-admins'),
    path('create', view = views.create_admin, name = 'create'),
    path('<int:id>/update', view = views.update_admin, name = 'update'),
    path('<int:id>/delete', view = views.delete_admin, name = 'delete'),
]
