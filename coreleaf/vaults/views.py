from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from cryptography.exceptions import InvalidTag

from accounts.encryption import decrypt_vault_key
from accounts.models import EncryptionKey
from .serializers import VaultCreateSerializer, VaultListSerializer
from .models import Item
from .vault_token import issue_vault_unlock_token, verify_vault_unlock_token


class VaultListCreateView(ListCreateAPIView):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Item.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.request.method == "GET":
            return VaultListSerializer
        return VaultCreateSerializer
    
    def _vault_unlock_check(self, request):
        token = request.headers.get("X-Vault-Unlock-Token")
        if not token:
            return Response({"error": "Missing X-Vault-Unlock-Token."}, status=status.HTTP_403_FORBIDDEN)
        user_id = verify_vault_unlock_token(token)
        if not user_id:
            return Response({"error": "Invalid or expired vault unlock token."}, status=status.HTTP_401_UNAUTHORIZED)
        if int(user_id) != int(request.user.id):
            return Response({"error": "Token subject mismatch."}, status=status.HTTP_401_UNAUTHORIZED)
        return None

    def list(self, request, *args, **kwargs):
        guard = self._vault_unlock_check(request)
        if guard is not None:
            return guard
        return super().list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        guard = self._vault_unlock_check(request)
        if guard is not None:
            return guard
        return super().create(request, *args, **kwargs)


class UnlockVaultView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        master_password = request.data.get("master_password")
        if not master_password:
            return Response({"error": "master_password is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            enc_record = EncryptionKey.objects.get(user=request.user)
        except EncryptionKey.DoesNotExist:
            return Response({"error": "No vault key found for user."}, status=status.HTTP_404_NOT_FOUND)

        try:
            # Attempt to decrypt; InvalidTag signals wrong master key
            decrypt_vault_key(master_password, enc_record.key)
        except InvalidTag:
            return Response({"error": "Invalid master password."}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print("Error:", e)
            return Response({"error": "Unable to unlock vault."}, status=status.HTTP_400_BAD_REQUEST)

        # Mark vault as unlocked using JWT token
        token = issue_vault_unlock_token(request.user.id)
        return Response({"vault_unlock_token": token}, status=status.HTTP_200_OK)
    