from rest_framework.serializers import ModelSerializer
from .models import Item


class VaultSerializer(ModelSerializer):
    class Meta:
        model = Item
        fields = ["id", "title", "user", "username", "password", "url", "notes", "created_at", "updated_at"]
