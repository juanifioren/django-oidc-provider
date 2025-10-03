from django.contrib.auth import get_user_model
from django.test import TestCase

from oidc_provider.admin import ClientForm
from oidc_provider.models import Client
from oidc_provider.models import ResponseType
from oidc_provider.tests.app.utils import create_fake_user

User = get_user_model()


class ClientFormTest(TestCase):
    """
    Test cases for ClientForm in admin.
    """

    def setUp(self):
        self.user = create_fake_user()
        self.code_response_type, _ = ResponseType.objects.get_or_create(
            value="code", defaults={"description": "code (Authorization Code Flow)"}
        )

    def test_creates_client_without_client_id_generates_random_one(self):
        """Test that creating a client without client_id generates a random 6-digit one."""
        form_data = {
            "name": "Test Client",
            "owner": self.user.pk,
            "client_type": "public",
            "response_types": [self.code_response_type.pk],
            "_redirect_uris": "http://example.com/callback",
        }

        form = ClientForm(data=form_data)
        self.assertTrue(form.is_valid(), f"Form errors: {form.errors}")

        # The form should generate a client_id
        client_id = form.clean_client_id()
        self.assertIsNotNone(client_id)
        self.assertEqual(len(client_id), 6)
        self.assertTrue(client_id.isdigit())
        self.assertTrue(1 <= int(client_id) <= 999999)

    def test_creates_client_with_custom_client_id_preserves_it(self):
        """Test that providing a custom client_id preserves it for new clients."""
        # Create and save a client first
        client = Client.objects.create(
            name="Existing Client",
            owner=self.user,
            client_type="public",
            client_id="custom-client-123",
        )
        client.response_types.add(self.code_response_type)

        form_data = {
            "name": "Existing Client Updated",
            "owner": self.user.pk,
            "client_type": "public",
            "response_types": [self.code_response_type.pk],
            "_redirect_uris": "http://example.com/callback",
            "client_id": "custom-client-123",
        }

        # Test updating existing client
        form = ClientForm(data=form_data, instance=client)
        self.assertTrue(form.is_valid(), f"Form errors: {form.errors}")

        # Should return the sanitized version of existing client_id
        client_id = form.clean_client_id()
        self.assertEqual(client_id, "custom-client-123")

    def test_sanitizes_existing_client_id_with_control_characters(self):
        """Test that existing client_id with control characters gets sanitized."""
        # Create a client with problematic client_id
        client = Client.objects.create(
            name="Problematic Client",
            owner=self.user,
            client_type="public",
            client_id="normalclient",  # Start with normal client_id
        )
        client.response_types.add(self.code_response_type)

        # Manually set problematic client_id to test sanitization
        client.client_id = "client\x00\x01test"  # Contains null byte and control char

        form_data = {
            "name": "Problematic Client",
            "owner": self.user.pk,
            "client_type": "public",
            "response_types": [self.code_response_type.pk],
            "_redirect_uris": "http://example.com/callback",
        }

        form = ClientForm(data=form_data, instance=client)
        self.assertTrue(form.is_valid(), f"Form errors: {form.errors}")

        # Should return sanitized client_id
        client_id = form.clean_client_id()
        self.assertEqual(client_id, "clienttest")  # Control characters removed
