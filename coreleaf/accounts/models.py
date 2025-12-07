from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    pass


class EncryptionKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    key = models.CharField(max_length=255)


    def __str__(self):
        return f"Encryption Key for {self.user.username}"