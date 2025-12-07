from .models import User
from rest_framework.test import APITestCase


class UserAPITestCase(APITestCase):
    def setUp(self):
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword",
            "first_name": "Test",
            "last_name": "User",
        }
        self.create_url = "/accounts/register/"
        self.profile_url = "/accounts/profile/1/"

    def test_user_registration(self):
        response = self.client.post(self.create_url, self.user_data, format="json")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["username"], self.user_data["username"])
        self.assertEqual(response.data["email"], self.user_data["email"])

    def test_user_profile_retrieval(self):
        # First, create a user
        self.client.post(self.create_url, self.user_data, format="json")

        # Now retrieve the user profile
        response = self.client.get(self.profile_url, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["username"], self.user_data["username"])
        self.assertEqual(response.data["email"], self.user_data["email"])

    def test_get_user_profile_authenticated(self):
        # Create a user
        self.client.post(self.create_url, self.user_data, format="json")

        # Authenticate the user
        response = self.client.post("/accounts/token/", {
            "username": self.user_data["username"],
            "password": self.user_data["password"]
        }, format="json")
        token = response.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)
        response = self.client.get("/accounts/me/", format="json")
        self.assertEqual(response.status_code, 200)