from django.db import models
from accounts.models import User


class Item(models.Model):
    title = models.CharField(max_length=255, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=255, blank=False, null=True)
    password = models.CharField(max_length=255)
    url = models.URLField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return f"{self.title} ({self.user.username})"
