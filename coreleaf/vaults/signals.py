from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Item
from django.core.cache import cache


@receiver([post_save, post_delete], sender=Item)
def invalidate_vault_list_cache(sender, instance, **kwargs):
    print("Clearing vault item list cache")

    cache.delete_pattern("*vault-list*")