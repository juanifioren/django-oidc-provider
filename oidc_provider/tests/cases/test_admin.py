from unittest.mock import MagicMock

from django.contrib import messages
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory
from django.test import TestCase

from oidc_provider.admin import ClientAdmin
from oidc_provider.admin import ClientForm
from oidc_provider.lib.utils.client_credentials import verify_secret
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


class ClientFormSecretTest(TestCase):
    def setUp(self):
        self.user = create_fake_user()
        self.code_response_type, _ = ResponseType.objects.get_or_create(
            value="code", defaults={"description": "code (Authorization Code Flow)"}
        )
        self.base_form_data = {
            "name": "Test Client",
            "owner": self.user.pk,
            "response_types": [self.code_response_type.pk],
            "_redirect_uris": "http://example.com/callback",
        }

    def _make_form(self, client_type, instance=None):
        data = {**self.base_form_data, "client_type": client_type}
        return ClientForm(data=data, instance=instance)

    def test_new_confidential_client_stores_hash_not_plaintext(self):
        form = self._make_form("confidential")
        self.assertTrue(form.is_valid(), form.errors)
        stored = form.cleaned_data["client_secret"]
        self.assertTrue(
            stored.startswith("pbkdf2") or stored.startswith("bcrypt") or "$" in stored
        )  # Hashing algoritm is dependent on settings and Django version, so we check for common patterns
        self.assertNotEqual(stored, form._plaintext_secret)

    def test_new_confidential_client_stashes_plaintext_on_form(self):
        form = self._make_form("confidential")
        self.assertTrue(form.is_valid(), form.errors)
        self.assertTrue(form._plaintext_secret)
        self.assertTrue(verify_secret(form._plaintext_secret, form.cleaned_data["client_secret"]))

    def test_new_public_client_has_no_secret(self):
        form = self._make_form("public")
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["client_secret"], "")
        self.assertEqual(form._plaintext_secret, "")

    def test_existing_confidential_client_with_secret_preserves_it(self):
        client = Client.objects.create(
            name="Existing",
            owner=self.user,
            client_type="confidential",
            client_secret="already-hashed-value",
        )
        client.response_types.add(self.code_response_type)
        form = self._make_form("confidential", instance=client)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["client_secret"], "already-hashed-value")
        self.assertEqual(form._plaintext_secret, "")

    def test_existing_confidential_client_without_secret_generates_new_hash(self):
        client = Client.objects.create(
            name="Existing No Secret",
            owner=self.user,
            client_type="confidential",
            client_secret="",
        )
        client.response_types.add(self.code_response_type)
        form = self._make_form("confidential", instance=client)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertTrue(form._plaintext_secret)
        self.assertTrue(verify_secret(form._plaintext_secret, form.cleaned_data["client_secret"]))


class ClientAdminSaveModelTest(TestCase):
    def setUp(self):
        self.user = create_fake_user()
        self.site = AdminSite()
        self.admin = ClientAdmin(Client, self.site)
        self.factory = RequestFactory()
        self.code_response_type, _ = ResponseType.objects.get_or_create(
            value="code", defaults={"description": "code (Authorization Code Flow)"}
        )

    def _make_request(self):
        request = self.factory.post("/")
        request.user = self.user
        request.session = "session"
        request._messages = FallbackStorage(request)
        return request

    def _make_form_with_plaintext(self, plaintext):
        form = MagicMock()
        form._plaintext_secret = plaintext
        return form

    def test_save_model_shows_warning_message_with_plaintext_for_confidential_client(self):
        obj = Client.objects.create(
            name="New Confidential",
            owner=self.user,
            client_type="confidential",
            client_secret="hashed-value",
        )
        request = self._make_request()
        self.admin.save_model(request, obj, self._make_form_with_plaintext("the-plain-secret"), change=False)

        stored = list(request._messages)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].level, messages.WARNING)
        self.assertIn("the-plain-secret", stored[0].message)

    def test_save_model_shows_no_message_for_public_client(self):
        obj = Client.objects.create(
            name="New Public",
            owner=self.user,
            client_type="public",
            client_secret="",
        )
        request = self._make_request()
        self.admin.save_model(request, obj, self._make_form_with_plaintext(""), change=False)

        self.assertEqual(list(request._messages), [])
