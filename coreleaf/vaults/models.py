from django.db import models
from accounts.models import User


class Vault(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_blob = models.BinaryField()
    iv = models.CharField(max_length=255, blank=True, null=True)
    version = models.PositiveIntegerField(default=1)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Vault for {self.user.username} (Version {self. version})"
        