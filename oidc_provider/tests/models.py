from django.db import models

from oidc_provider.models import AbstractClient


class Client(AbstractClient):
    custom_field = models.CharField(max_length=255)
