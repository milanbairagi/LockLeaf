from django.urls import path

from .views import VaultBlobListCreateView

# from .views import VaultListCreateView, UnlockVaultView, RetrieveUpdateVaultView


urlpatterns = [
    path("blobs/", VaultBlobListCreateView.as_view(), name="vault-blob-list-create"),

    # path("list-create/", VaultListCreateView.as_view(), name="vault-list-create"),
    # path("unlock/", UnlockVaultView.as_view(), name="unlock-vault"),
    # path("retrieve-update/<int:pk>/", RetrieveUpdateVaultView.as_view(), name="retrieve-update-vault"),
]
