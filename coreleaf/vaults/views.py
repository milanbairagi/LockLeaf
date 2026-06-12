from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.core.cache import cache
from .serializers import VaultSerializer
from .models import Item


class VaultBlobListCreateView(ListCreateAPIView):
    serializer_class = VaultSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Item.objects.filter(user=self.request.user)

    def list(self, request, *args, **kwargs):
        # Check cache first
        cache_key = f"vault-blob-list-user-{request.user.id}"
        cached_response = cache.get(cache_key)

        if cached_response:
            print("Serving vault item list from cache")
            return Response(cached_response)

        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)

        # cache the response for 15 minutes
        cache.set(cache_key, serializer.data, 60 * 15)
        return Response(serializer.data)
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data={
            **request.data,
            "user": request.user.id,
        })
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=201, headers=headers)
