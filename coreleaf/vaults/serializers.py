from rest_framework.serializers import ModelSerializer
from .models import Item


class VaultCreateSerializer(ModelSerializer):
    class Meta:
        model = Item
        fields = ["id", "title", "user", "username", "password", "url", "notes", "created_at", "updated_at"]


class VaultListSerializer(ModelSerializer):
    class Meta:
        model = Item
        fields = ["id", "title", "username", "url", "created_at", "updated_at"]