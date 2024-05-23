import json
from django.core.serializers.json import DjangoJSONEncoder
from helpers import response_error, response_success, hash_password, compare_password, \
    generate_token, serialize_model_instance, validate_request
from rest_framework.decorators import api_view
from user.decorators import verify_token, check_permission
from user_model.models import User, USER_ROLE


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
