import uuid

from oidc_provider.models import Client, ResponseType


def create_client(redirect_uris=None, name=None, response_types=['code']):
    client = Client()
    client._redirect_uris = redirect_uris
    client.name = name or uuid.uuid4().hex
    client.client_id = uuid.uuid4().hex
    client.client_secret = uuid.uuid4().hex
    client.save()

    client.response_types.set(ResponseType.objects.filter(value__in=response_types).all())

    return client
