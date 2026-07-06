from rest_framework.views import APIView
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.core.cache import cache
import base64
from .serializers import VaultSerializer
from .models import Vault


class VaultBlobSyncView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        return self._sync_vault(request)
    
    def put(self, request):
        return self._sync_vault(request)
    
    def patch(self, request):
        return self._sync_vault(request)
    
    def _sync_vault(self, request):
        vault = Vault.objects.filter(user=request.user).order_by('-version').first()
        if not vault:
            raise ValidationError({"detail": "No vault found for the user."})

        # If the client version matches the server version, we can create a new vault entry with the updated data
        client_version = request.data.get("version", 1)
        if client_version == vault.version:
            data = request.data
            encrypted_blob = data.get("encrypted_blob", vault.encrypted_blob)
            version = vault.version + 1
            
            # Convert base64 to bytes if the encrypted_blob is a string
            if isinstance(encrypted_blob, str):
                try:
                    encrypted_blob = base64.b64decode(encrypted_blob)
                except Exception as e:
                    raise ValidationError({"encrypted_blob": "Invalid base64 string."})

            # TODO: Delete the old vault entry if needed, or keep it for version history.

            # Creating a new vault with the updated data
            new_vault = Vault.objects.create(
                user=request.user,
                encrypted_blob=encrypted_blob,
                iv=vault.iv,
                version=version
            )
            serializer = VaultSerializer(new_vault)
            return Response(serializer.data)
        else:
            return Response({"detail": "Vault is already up to date."}, status=status.HTTP_400_BAD_REQUEST)

class VaultBlobListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # Check cache first
        cache_key = f"vault-blob-list-user-{request.user.id}"
        cached_response = cache.get(cache_key)

        if cached_response:
            print("Serving vault item list from cache")
            return Response(cached_response)

        vault = Vault.objects.filter(user=request.user).order_by('-version').first()
        if not vault:
            raise ValidationError({"detail": "No vault found for the user."})
        serializer = VaultSerializer(vault)

        # cache the response for 15 minutes
        cache.set(cache_key, serializer.data, 60 * 15)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        serializer = VaultSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        if Vault.objects.filter(user=self.request.user).exists():
            raise ValidationError({"detail": "Vault already exists for this user."})
        
        serializer.save(user=self.request.user)

        return Response(serializer.data, status=status.HTTP_201_CREATED)
