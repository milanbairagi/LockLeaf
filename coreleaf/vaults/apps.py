from django.apps import AppConfig


class VaultsConfig(AppConfig):
    name = 'vaults'

    def ready(self):
        from . import signals
