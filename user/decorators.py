from functools import wraps
import jwt
from django.db.models import Q
from rest_framework import status
from django.conf import settings
from helpers import response_error
from model.models import USER_ROLE, User


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


def check_permission(f):
    @wraps(f)
    def decorated(request, *args, **kwargs):
        try:
            admin = User.objects.get(Q(role = USER_ROLE['ADMIN']) | Q(role = USER_ROLE['SUPER_ADMIN']),
                                     username = request.username, deleted = False)
            request.me_id = admin.id

            return f(request, *args, **kwargs)
        except User.DoesNotExist:
            return response_error('Account does not exists!', status.HTTP_404_NOT_FOUND)
        # except:
        #     return response_error('Unauthorized', status.HTTP_401_UNAUTHORIZED)

    return decorated
