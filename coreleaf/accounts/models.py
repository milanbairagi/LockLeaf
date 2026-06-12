from django.db import models
from django.contrib.auth.models import AbstractUser
from .managers import UserManager


class User(AbstractUser):
    email = models.EmailField(unique=True)

    objects = UserManager()

    username = None
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []