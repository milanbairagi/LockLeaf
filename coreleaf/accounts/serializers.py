from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "password"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class MasterKeyInputSerializer(serializers.Serializer):
    """Serializer for setting master key."""
    master_key = serializers.CharField(required=True, help_text="Master key to encrypt the vault key")


class MasterKeyOutputSerializer(serializers.Serializer):
    """Serializer for retrieving master key status."""
    has_master_key = serializers.BooleanField(help_text="Indicates if the user has a master key set")