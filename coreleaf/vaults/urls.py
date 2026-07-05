from django.urls import path

from .views import VaultBlobListCreateView, VaultBlobSyncView


urlpatterns = [
    path("blobs/", VaultBlobListCreateView.as_view(), name="vault-blob-list-create"),
    path("blobs/sync/", VaultBlobSyncView.as_view(), name="vault-blob-sync"),
]