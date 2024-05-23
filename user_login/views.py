from django.db.models import Q
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view

from helpers import response_error, compare_password, generate_token, response_success
from user_model.models import User, USER_ROLE


# Create your views here.
@api_view(['POST'])
def admin_login(request):
    try:
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username or not password:
            return response_error('All fields are required!')

        user = User.objects.get(Q(role = USER_ROLE['ADMIN']) | Q(role = USER_ROLE['SUPER_ADMIN']),
                                username = username, deleted = False)
        if compare_password(password, user.password):
            response = {
                'token': generate_token(username),
                'exp': '7d',
                'type': 'Bearer'
            }

            return response_success('Login Successfully', response)
        return response_error('Incorrect username or password', 401)
    except User.DoesNotExist:
        return response_error('Account does not exists!')
    except:
        return response_error('Server error', status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def login(request):
    try:
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username or not password:
            return response_error('All fields are required!')

        user = User.objects.get(username = username, role = USER_ROLE['USER'], deleted = False)
        if compare_password(password, user.password):
            response = {
                'token': generate_token(username),
                'exp': '7d',
                'type': 'Bearer'
            }

            return response_success('Login Successfully', response)
        return response_error('Incorrect username or password', 401)
    except User.DoesNotExist:
        return response_error('Account does not exists!', 404)
