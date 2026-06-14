from rest_framework import serializers
from rest_framework.serializers import ModelSerializer, ValidationError
from .models import Item


class VaultSerializer(ModelSerializer):
    iv = serializers.CharField(allow_blank=False, allow_null=False)

    class Meta:
        model = Item
        fields = ["id", "title", "user", "username", "password", "iv", "url", "notes", "created_at", "updated_at"]
        read_only_fields = ["user", "created_at", "updated_at"]

    def validate_iv(self, value):
        if not value or not value.strip():
            raise ValidationError("This field cannot be empty.")
        return value

    def update(self, instance, validated_data):
        if "iv" in validated_data and validated_data["iv"] != instance.iv:
            raise ValidationError({"iv": "This field cannot be changed once it is set."})
        return super().update(instance, validated_data)