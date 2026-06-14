from rest_framework.test import APITestCase
from rest_framework import status
from django.shortcuts import reverse
from accounts.models import User


class UserAPITestCase(APITestCase):
    def setUp(self):
        self.user_data = {
            "email": "test@example.com",
            "password": "testpassword",
            "first_name": "Test",
            "last_name": "User",
        }
        self.create_url = reverse("user-register")
        self.profile_url = reverse("user-me")
        self.user = None
    
    def generate_token_for_user(self, user):
        """Helper method to generate auth token for a user"""
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)
    
    def get_user_or_create(self):
        """Helper method to get or create a user for testing"""
        if not self.user:
            self.user = User.objects.create_user(**self.user_data)
        return self.user

    def test_user_registration(self):
        response = self.client.post(self.create_url, self.user_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["email"], self.user_data["email"])
        self.assertTrue(response.data["salt"])

    def test_user_profile_retrieval(self):
        user = self.get_user_or_create()
        token = self.generate_token_for_user(user)

        # Authenticate the user
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)

        # Now retrieve the user profile
        response = self.client.get(self.profile_url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], self.user_data["email"])
        self.assertEqual(response.data["first_name"], self.user_data["first_name"])
        self.assertEqual(response.data["last_name"], self.user_data["last_name"])
        self.assertTrue(response.data["salt"])

    def test_salt_view_is_read_only(self):
        user = self.get_user_or_create()
        token = self.generate_token_for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)

        response = self.client.get(reverse("user-salt"), format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["salt"])

        response = self.client.post(reverse("user-salt"), {"salt": "new-salt"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)