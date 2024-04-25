import json

from django.core.serializers.json import DjangoJSONEncoder

from helpers import response_error, response_success, is_valid_phone, is_valid_email, hash_password, compare_password, \
    generate_token, serialize_model_instance, validate_request
from .models import User
from rest_framework.decorators import api_view
from user.decorators import verify_token
from .serializers import UserSerializer


# Create your views here.
@api_view(['POST'])
def register(request):
    if request.method == 'POST':
        username = request.POST.get("username")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        mobile = request.POST.get("mobile")
        password = request.POST.get("password")
        address = request.POST.get("address")

        # In this if statement, checking that all fields are available.
        if username and first_name and last_name and email and mobile and password:
            is_not_pass_validate = validate_request({
                'username': username,
                'mobile': mobile,
                'email': email
            })

            if is_not_pass_validate['error']:
                return response_error('Error', 400, is_not_pass_validate['detail'])

            response_data = User.objects.create(username = username, first_name = first_name,
                                                last_name = last_name, email = email,
                                                mobile = mobile, password = hash_password(password),
                                                address = address)
            if response_data:
                return response_success('Register Successfully')
            return response_error('Unable to register user!')

        return response_error('All fields are required!')
    return response_error(f"Method {request.method} is not supported!")


@api_view(['POST'])
def login(request):
    username = request.POST.get("username")
    password = request.POST.get("password")

    if not username or not password:
        return response_error('All fields are required!')

    try:
        user = User.objects.get(username = username, deleted = False)
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


@verify_token
@api_view(['GET'])
def info(request):
    user = User.objects.get(username = request.username, deleted = False)

    response = {
        'user': json.loads(json.dumps(serialize_model_instance(user, ['password', 'deleted']),
                                      cls = DjangoJSONEncoder))
    }
    return response_success('Success', response)


@verify_token
@api_view(['PUT'])
def update_me(request):
    username = request.POST.get("username")
    first_name = request.POST.get("first_name")
    last_name = request.POST.get("last_name")
    email = request.POST.get("email")
    mobile = request.POST.get("mobile")
    address = request.POST.get("address")

    if username and first_name and last_name and email and mobile:
        me = User.objects.get(username = request.username)

        is_not_pass_validate = validate_request({
            'username': username,
            'mobile': mobile,
            'email': email
        })

        if is_not_pass_validate['error']:
            return response_error('Error', 400, is_not_pass_validate['detail'])

        me.username = username
        me.first_name = first_name
        me.last_name = last_name
        me.email = email
        me.mobile = mobile
        me.address = address
        me.save()

        return response_success('Update Successfully')

    return response_error('All fields are required!')
