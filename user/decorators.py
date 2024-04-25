from functools import wraps

import jwt
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from rest_framework import status
from django.conf import settings

from helpers import response_error


def verify_token(f):
    @wraps(f)
    def decorated(request, *args, **kwargs):
        token = request.META.get('HTTP_AUTHORIZATION', '')
        if not token:
            return response_error('Unauthorized', status.HTTP_401_UNAUTHORIZED)

        try:
            token = token[7:]
            decoded = jwt.decode(token, settings.SECRET_KEY, algorithms = ['HS256'])
            request.username = decoded['username']
        except jwt.ExpiredSignatureError:
            return response_error('Token has expired', status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return response_error('Invalid token', status.HTTP_401_UNAUTHORIZED)

        return f(request, *args, **kwargs)

    return decorated
