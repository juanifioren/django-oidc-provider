from unittest import skip
import django
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model

from oidc_provider.models import get_client_model, Client
from oidc_provider.tests.models import CustomClient

UserModel = get_user_model()


class TestModels(TestCase):

    def test_retrieve_default_client_model(self):
        client = get_client_model()
        self.assertEqual(Client, client)

    @override_settings(OIDC_CLIENT_MODEL='tests.CustomClient')
    def test_retrireve_custom_client_model(self):
        client = get_client_model()
        self.assertEqual(CustomClient, client)


@override_settings(OIDC_CLIENT_MODEL='tests.CustomClient')
class TestCustomClientModel(TestCase):

    @skip(django.VERSION <= (1, 7))
    def test_custom_client_model(self):
        """
        If a custom client model is installed, it should be present in
        the related objects.
        """
        related_object_names = [
            f.name for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertIn("tests_customclient_set", related_object_names)

    @override_settings(OIDC_CLIENT_MODEL='IncorrectModelFormat')
    def test_custom_application_model_incorrect_format(self):
        self.assertRaises(ValueError, get_client_model)

    @override_settings(OIDC_CLIENT_MODEL='tests.ClientNotInstalled')
    def test_custom_application_model_incorrect_format(self):
        self.assertRaises(LookupError, get_client_model)
