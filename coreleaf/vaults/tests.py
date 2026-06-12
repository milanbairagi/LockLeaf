from rest_framework.test import APITestCase
from rest_framework import status
from accounts.models import User
from django.core.cache import cache
from django.shortcuts import reverse
from .models import Item


class VaultBlobListCreateViewTests(APITestCase):
    """Tests for VaultBlobListCreateView"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(email="testuser@example.com", password="testpass123")
        self.other_user = User.objects.create_user(email="otheruser@example.com", password="testpass123")
        self.url = reverse("vault-blob-list-create")
        
        self.item1_data = {"title": "test item 1", "username": "user1", "password": "pass1", "url":"https://example1.com", "notes": "notes1"}
        self.item2_data = {"title": "test item 2", "username": "user2", "password": "pass2", "url":"https://example2.com", "notes": "notes2"}
        
        # Clear cache before each test
        cache.clear()

    def generate_token_for_user(self, user):
        """Helper method to generate auth token for a user"""
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def test_create_requires_authentication(self):
        """Test that unauthenticated requests cannot create items"""
        response = self.client.post(self.url, self.item1_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_requires_authentication(self):
        """Test that unauthenticated requests cannot list items"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_authenticated_user_item(self):
        """Test that authenticated user can create items"""
        token = self.generate_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.post(self.url, self.item1_data, format="json")
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["title"], self.item1_data["title"])
        self.assertEqual(response.data["username"], self.item1_data["username"])
        self.assertEqual(response.data["password"], self.item1_data["password"])
        self.assertEqual(response.data["url"], self.item1_data["url"])
        self.assertEqual(response.data["notes"], self.item1_data["notes"])
        self.assertEqual(response.data["user"], self.user.id)
        
        # Verify item was created in database
        self.assertEqual(Item.objects.filter(user=self.user).count(), 1)

    def test_list_authenticated_user_items(self):
        """Test that authenticated user can list their own items"""
        # Create items for both users
        Item.objects.create(user=self.user, **self.item1_data)
        Item.objects.create(user=self.user, **self.item2_data)
        other_item = Item.objects.create(user=self.other_user, title="other item", username="otheruser", password="otherpass", url="https://other.com", notes="other notes")
        
        token = self.generate_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)


class VaultBlobUpdateDestroyViewTests(APITestCase):
    """Tests for VaultBlobUpdateDestroyView"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(email="test@example.com", password="testpassword")
        self.other_user = User.objects.create_user(email="other@example.com", password="otherpassword")

        self.item = Item.objects.create(user=self.user, title="test item", username="testuser", password="testpass", url="https://example.com", notes="test notes")
        self.url = reverse("vault-blob-update-destroy", kwargs={"pk": self.item.id})

    def generate_token_for_user(self, user):
        """Helper method to generate auth token for a user"""
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)
    
    def test_update_requires_authentication(self):
        """Test that unauthenticated requests cannot update items"""
        response = self.client.put(self.url, {"title": "updated title"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_destroy_requires_authentication(self):
        """Test that unauthenticated requests cannot delete items"""
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_update_authenticated_user_item(self):
        """Test that authenticated user can update their own items"""
        token = self.generate_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        updated_item_data = {"title": "updated title", "username": "updateduser", "password": "updatedpass", "url": "https://updated.com", "notes": "updated notes"}
        
        response = self.client.patch(self.url, updated_item_data, format="json")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["title"], updated_item_data["title"])
        self.assertEqual(response.data["username"], updated_item_data["username"])
        self.assertEqual(response.data["password"], updated_item_data["password"])
        self.assertEqual(response.data["url"], updated_item_data["url"])
        self.assertEqual(response.data["notes"], updated_item_data["notes"])
        self.assertEqual(response.data["user"], self.user.id)

    def test_update_other_user_item(self):
        """Test that authenticated user cannot update other user's items"""
        other_item = Item.objects.create(user=self.other_user, title="other item", username="otheruser", password="otherpass", url="https://other.com", notes="other notes")
        other_url = reverse("vault-blob-update-destroy", kwargs={"pk": other_item.id})

        token = self.generate_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.put(other_url, {"title": "hacked title"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_cannot_change_user_field_on_update(self):
        """Test that authenticated user cannot change the user field of an item"""
        token = self.generate_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        # Try to update item and change user field to other_user
        updated_item_data = {
            "title": "updated title",
            "username": "updateduser",
            "password": "updatedpass",
            "url": "https://updated.com",
            "notes": "updated notes",
            "user": self.other_user.id  # Attempt to change owner
        }
        
        response = self.client.patch(self.url, updated_item_data, format="json")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify user field is still the original user, not changed
        self.assertEqual(response.data["user"], self.user.id)
        # Refresh from DB to confirm
        self.item.refresh_from_db()
        self.assertEqual(self.item.user, self.user)

    def test_destroy_other_user_item(self):
        """Test that authenticated user cannot delete other user's items"""
        other_item = Item.objects.create(user=self.other_user, title="other item", username="otheruser", password="otherpass", url="https://other.com", notes="other notes")
        other_url = reverse("vault-blob-update-destroy", kwargs={"pk": other_item.id})

        token = self.generate_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.delete(other_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_destroy_authenticated_user_item(self):
        """Test that authenticated user can delete their own items"""
        token = self.generate_token_for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        response = self.client.delete(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        # Verify item was deleted from database
        self.assertFalse(Item.objects.filter(id=self.item.id).exists())