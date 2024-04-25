import bcrypt
from django.http import HttpResponse
import json
import re
import jwt
import datetime
from django.conf import settings

from model.models import User


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def compare_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password[2:len(hashed_password) - 1].encode('utf-8'))


EMAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
PHONE_REGEX = r'^(\+?84|0)([3|5|7|8|9])+([0-9]{8})$'


def response_success(message = '', data = None, status_code = 200):
    if data is None:
        data = {}

    return HttpResponse(json.dumps({
        'status': 'Success',
        'status_code': status_code,
        'message': message,
        'data': data
    }), content_type = 'application/json')


def response_error(message = '', status_code = 400, error = None):
    if error is None:
        error = {}

    return HttpResponse(json.dumps({
        'status': 'Failed',
        'status_code': status_code,
        'message': message,
        'error': error
    }), content_type = 'application/json')


def is_valid_phone(number):
    return re.match(PHONE_REGEX, number) is not None


def is_valid_email(email):
    return re.fullmatch(EMAIL_REGEX, email) is not None


def generate_token(username):
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days = 7)
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm = 'HS256')

    return token


def serialize_model_instance(instance, exclude):
    data = {}
    for field in instance._meta.fields:
        field_name = field.name
        if field_name in exclude:
            continue
        field_value = getattr(instance, field_name)
        data[field_name] = field_value
    return data


def validate_request(data):
    is_email_existed = User.objects.filter(email = data['email'], deleted = False)
    is_phone_existed = User.objects.filter(mobile = data['mobile'], deleted = False)
    is_username_existed = User.objects.filter(username = data['username'], deleted = False)

    error = {}
    if is_username_existed:
        error['username'] = 'Username already exists!'

    if is_email_existed:
        error['email'] = 'Email already exists!'

    if is_phone_existed:
        error['mobile'] = 'Phone number already exists!'

    if len(str(data['mobile'])) != 10 or not is_valid_phone(data['mobile']):
        error['mobile'] = 'Phone number is not in the correct format!'

    if not is_valid_email(data['email']):
        error['email'] = 'Email is not in the correct format!'

    if error:
        return {
            'error': True,
            'detail': error
        }

    return {
        'error': False,
        'detail': None
    }
