from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from .serializers import UserSerializer
from .models import User


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