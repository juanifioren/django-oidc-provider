from django.db import models

from oidc_provider.models import AbstractClient


class CustomClient(AbstractClient):
    custom_field = models.CharField(max_length=255)
