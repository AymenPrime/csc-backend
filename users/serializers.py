from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'password', 'picture', 'verification_code', 'points']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        # Create a new user using the custom User model
        user = User.objects.create_user(
            name=validated_data['name'],
            password=validated_data['password'],
            picture=validated_data.get('picture'),
            verification_code=validated_data.get('verification_code'),
            points=validated_data.get('points', 0),
        )
        return user