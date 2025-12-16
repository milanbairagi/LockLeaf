from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer
from .models import User, EncryptionKey
from .encryption import encrypt_vault_key, decrypt_vault_key


class UserCreateView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class UserRetrieveUpdate(RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class UserProfile(RetrieveUpdateAPIView):
    """View to retrieve and update the authenticated user's profile."""
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class MasterKeyView(APIView):
    
    def post(self, request, *args, **kwargs):
        """Store the vault_key (encrypted) for the authenticated user using master key."""

        user = request.user
        master_key = request.data.get("master_key", None)

        if master_key is None:
            return Response({"error": "Master key is required."}, status=400)
        
        if not user.is_authenticated:
            return Response({"error": "Authentication required."}, status=401)

        # Check if user already has an master key stored
        if EncryptionKey.objects.filter(user=user).exists():
            return Response({"error": "Master key already set."}, status=400)
        
        encrypted_vault_key = encrypt_vault_key(master_key)       

        # Store the encrypted vault key
        EncryptionKey.objects.create(user=user, key=encrypted_vault_key)
        return Response({"message": "Master key set successfully."}, status=201)
    
