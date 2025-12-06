from django.contrib import admin
from .models import Item, encryptionKey


admin.site.register(Item)
admin.site.register(encryptionKey)