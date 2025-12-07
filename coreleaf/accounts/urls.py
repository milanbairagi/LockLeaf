from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import UserCreateView, UserRetrieveUpdate


urlpatterns = [
    path("register/", UserCreateView.as_view(), name="user-register"),
    path("profile/<int:pk>/", UserRetrieveUpdate.as_view(), name="user-profile"),
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]