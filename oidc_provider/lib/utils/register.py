import uuid
from oidc_provider.models import Client
 
def create_client(redirect_uris=None, name=None, response_type = 'code'):
    client = Client()
    client._redirect_uris = redirect_uris
    client.response_type = response_type    
    client.name = name
    client.client_id = uuid.uuid4().hex
    client.client_secret = uuid.uuid4().hex
    
    return client
    
    

