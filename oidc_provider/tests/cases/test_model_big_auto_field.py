from django.db import models
from django.test import TestCase

from oidc_provider.models import BaseModel
from oidc_provider.models import Client
from oidc_provider.models import Code
from oidc_provider.models import ResponseType
from oidc_provider.models import RSAKey
from oidc_provider.models import Token
from oidc_provider.models import UserConsent


class BigAutoFieldTest(TestCase):
    """
    Test to verify that all models in oidc_provider use BigAutoField as primary key.
    This ensures compatibility with modern Django projects (3.2+).
    """

    def test_models_inherit_from_basemodel(self):
        """
        Verify that all required models inherit from BaseModel.
        """
        models_to_check = [
            Client,
            Code,
            ResponseType,
            Token,
            UserConsent,
            RSAKey,
        ]

        for model_class in models_to_check:
            self.assertTrue(
                issubclass(model_class, BaseModel),
                f"{model_class.__name__} should inherit from BaseModel.",
            )

    def test_id_fields_are_bigautofield(self):
        """
        Verify that the 'id' field of all models is BigAutoField.
        """
        models_to_check = {
            "Client": Client,
            "Code": Code,
            "ResponseType": ResponseType,
            "RSAKey": RSAKey,
            "Token": Token,
            "UserConsent": UserConsent,
        }

        for model_name, model_class in models_to_check.items():
            id_field = model_class._meta.get_field("id")

            self.assertIsInstance(
                id_field,
                models.BigAutoField,
                f"The 'id' field of {model_name} should be BigAutoField.",
            )

    def test_bigautofield_is_primary_key(self):
        """
        Verify that the BigAutoField is set as the primary key.
        """
        models_to_check = {
            "Client": Client,
            "Code": Code,
            "ResponseType": ResponseType,
            "RSAKey": RSAKey,
            "Token": Token,
            "UserConsent": UserConsent,
        }

        for model_name, model_class in models_to_check.items():
            id_field = model_class._meta.get_field("id")

            self.assertTrue(
                id_field.primary_key,
                f"The 'id' field of {model_name} should be the primary key.",
            )
