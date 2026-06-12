from django.urls import path

from .views import VaultBlobListCreateView, VaultBlobUpdateDestroyView


urlpatterns = [
    path("blobs/", VaultBlobListCreateView.as_view(), name="vault-blob-list-create"),
    path("blobs/<int:pk>/", VaultBlobUpdateDestroyView.as_view(), name="vault-blob-update-destroy"),
]