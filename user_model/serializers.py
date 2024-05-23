from rest_framework import serializers
from user_model.models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ['password', 'deleted']
