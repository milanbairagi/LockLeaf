from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import UserCreateView, UserProfile, MasterKeyView


urlpatterns = [
    path("register/", UserCreateView.as_view(), name="user-register"),
    path("me/", UserProfile.as_view(), name="user-me"),
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("master-key/", MasterKeyView.as_view(), name="master-key"),
]