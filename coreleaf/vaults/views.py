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
from .encryption import encrypt_data, decrypt_data


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
            return Response({"error": "Missing X-Vault-Unlock-Token."}, status=status.HTTP_403_FORBIDDEN), None
        user_id, vault_key = verify_vault_unlock_token(token)
        if not user_id or not vault_key:
            return Response({"error": "Invalid or expired vault unlock token."}, status=status.HTTP_401_UNAUTHORIZED), None
        if int(user_id) != int(request.user.id):
            return Response({"error": "Token subject mismatch."}, status=status.HTTP_401_UNAUTHORIZED), None
        return None, vault_key

    def list(self, request, *args, **kwargs):
        guard, vault_key  = self._vault_unlock_check(request)
        if guard is not None:
            return guard
        
        queryset = self.filter_queryset(self.get_queryset())
        # Decrypt usernames before serialization
        for item in queryset:
            if item.username:
                item.username = decrypt_data(vault_key, item.username).decode()
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
            

    def create(self, request, *args, **kwargs):
        guard, vault_key = self._vault_unlock_check(request)
        if guard is not None:
            return guard
        
        user = request.user
        username = request.data.pop("username", None)
        password = request.data.pop("password", None)
        notes = request.data.pop("notes", None)

        encrypted_username = encrypt_data(vault_key, username.encode()) if username else None
        encrypted_password = encrypt_data(vault_key, password.encode()) if password else None
        encrypted_notes = encrypt_data(vault_key, notes.encode()) if notes else None

        serializer = self.get_serializer(data={
                                        **request.data,
                                        "user": user.id,
                                        "username": encrypted_username,
                                        "password": encrypted_password,
                                        "notes": encrypted_notes,
                                    })
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


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
            vault_key = decrypt_vault_key(master_password, enc_record.key)
        except InvalidTag:
            return Response({"error": "Invalid master password."}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print("Error:", e)
            return Response({"error": "Unable to unlock vault."}, status=status.HTTP_400_BAD_REQUEST)

        # Mark vault as unlocked using JWT token with embedded vault key
        token = issue_vault_unlock_token(request.user.id, vault_key)
        return Response({"vault_unlock_token": token}, status=status.HTTP_200_OK)
    