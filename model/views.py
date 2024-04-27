import json
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Q

from constants import PER_PAGE
from helpers import response_error, response_success, hash_password, compare_password, \
    generate_token, serialize_model_instance, validate_request
from .models import User, USER_ROLE
from rest_framework.decorators import api_view
from user.decorators import verify_token, check_permission
from .serializers import UserSerializer
from rest_framework import status


# Create your views here.

# Authentication
@api_view(['POST'])
def register(request):
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
            'id': None,
            'username': username,
            'mobile': mobile,
            'email': email
        }, USER_ROLE['USER'])

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


@api_view(['PUT'])
@verify_token
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
            'id': me.id,
            'username': username,
            'mobile': mobile,
            'email': email
        }, USER_ROLE['USER'])

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


# Admin Management
@api_view(['GET'])
@verify_token
@check_permission
def get_admins(request):
    queries = handle_query(request)

    admins = (User.objects
              .filter(deleted = False, role = USER_ROLE['ADMIN'])
              .order_by(queries['field']))

    if queries['q'] is not None:
        admins = admins.filter(username__icontains = queries['q'].strip())

    admins = admins[queries['from_page']:queries['to_page']]

    return response_success('Success', UserSerializer(admins, many = True).data)


@api_view(['POST'])
@verify_token
@check_permission
def create_admin(request):
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
            'id': None,
            'username': username,
            'mobile': mobile,
            'email': email
        }, USER_ROLE['ADMIN'])

        if is_not_pass_validate['error']:
            return response_error('Error', 400, is_not_pass_validate['detail'])

        response_data = User.objects.create(username = username, first_name = first_name,
                                            last_name = last_name, email = email,
                                            mobile = mobile, password = hash_password(password),
                                            address = address, role = USER_ROLE['ADMIN'])
        if response_data:
            return response_success('Created Successfully', {}, status.HTTP_201_CREATED)
        return response_error('Unable to create admin!')

    return response_error('All fields are required!')


@api_view(['PUT'])
@verify_token
@check_permission
def update_admin(request, id):
    try:
        username = request.POST.get("username")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        mobile = request.POST.get("mobile")
        address = request.POST.get("address")

        if username and first_name and last_name and email and mobile:
            admin = User.objects.get(pk = id, role = USER_ROLE['ADMIN'], deleted = False)

            is_not_pass_validate = validate_request({
                'id': id,
                'username': username,
                'mobile': mobile,
                'email': email
            }, USER_ROLE['ADMIN'])

            if is_not_pass_validate['error']:
                return response_error('Error', 400, is_not_pass_validate['detail'])

            admin.username = username
            admin.first_name = first_name
            admin.last_name = last_name
            admin.email = email
            admin.mobile = mobile
            admin.address = address
            admin.save()

            return response_success('Updated Successfully')

        return response_error('All fields are required!')
    except User.DoesNotExist:
        return response_error('Admin account does not exists!', status.HTTP_404_NOT_FOUND)
    except:
        return response_error('Bad Request', status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
@verify_token
@check_permission
def delete_admin(request, id):
    try:
        if id == request.me_id:
            return response_error('Cant delete yourself', status.HTTP_400_BAD_REQUEST)

        admin = User.objects.get(pk = id, role = USER_ROLE['ADMIN'], deleted = False)
        admin.deleted = True
        admin.save()

        return response_success('Deleted Successfully')
    except User.DoesNotExist:
        return response_error('Admin account does not exists!', status.HTTP_404_NOT_FOUND)
    except:
        return response_error('Bad Request', status.HTTP_400_BAD_REQUEST)


def handle_query(request):
    q = request.GET.get('q')
    page_query = request.GET.get('page')
    sort_order = request.GET.get('sort_order')
    field = request.GET.get('field')

    if sort_order and field:
        field = '-' + field if sort_order == 'desc' else field
    else:
        field = '-created_at'

    page = int(page_query) if page_query is not None else 1
    from_page = PER_PAGE * (page - 1)
    to_page = PER_PAGE

    return {
        'q': q,
        'sort_order': sort_order,
        'field': field,
        'from_page': from_page,
        'to_page': to_page,
        'page': page
    }
