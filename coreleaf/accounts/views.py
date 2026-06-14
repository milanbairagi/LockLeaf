from secrets import token_urlsafe
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from .models import User


class UserCreateView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class UserProfile(RetrieveUpdateAPIView):
    """View to retrieve and update the authenticated user's profile."""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
    

class SaltView(APIView):
    """View to retrieve the salt for the authenticated user."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user.salt:
            # Generate a new salt if it doesn't exist
            user.salt = token_urlsafe(16)
            user.save()
        return Response({"salt": user.salt})