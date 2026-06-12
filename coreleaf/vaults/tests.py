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