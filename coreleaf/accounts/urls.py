from django.urls import path
from .views import UserCreateView, UserRetrieveUpdate


urlpatterns = [
    path("register/", UserCreateView.as_view(), name="user-register"),
    path("profile/<int:pk>/", UserRetrieveUpdate.as_view(), name="user-profile"),
]