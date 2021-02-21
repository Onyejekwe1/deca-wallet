from typing import Dict, List

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from deca_wallet.models import User, Elite, Noob, Wallet, WalletTransaction
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import make_password


class UserSerializer(serializers.ModelSerializer):
    """ Maps user data that will later be transformed to the user model"""
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    username = serializers.CharField(
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(min_length=8)

    class Meta:
        model = User
        fields = '__all__'

    def validate(self, data):
        email_validation = 'email' in data and data['email']
        validate_password(password=data['password'].strip())
        errors: Dict[str, List[str]] = {}

        if not email_validation:
            errors['email'] = ['Invalid email']

        if len(errors):
            raise serializers.ValidationError(errors)

        data['password'] = make_password(data.get('password'))
        serialized_user = {
            'first_name': data['first_name'],
            'last_name': data['last_name'],
            'email': data['email'],
            'password': data['password'],
            "is_admin": data.get("is_admin", False)
        }

        return serialized_user


class EliteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Elite
        fields = '__all__'


class NoobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Noob
        fields = '__all__'


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = '__all__'


class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = '__all__'
