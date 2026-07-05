from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Vault
from django.core.cache import cache


@receiver([post_save, post_delete], sender=Vault)
def invalidate_vault_list_cache(sender, instance, **kwargs):
    # cache.delete_pattern("*vault-list*")
    cache.delete(f"vault-blob-list-user-{instance.user.id}")