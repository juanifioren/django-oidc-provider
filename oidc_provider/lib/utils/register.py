from datetime import timedelta
import time
import uuid

from django.utils import timezone
from hashlib import md5

from oidc_provider.lib.utils.common import get_issuer, get_rsa_key
from oidc_provider.models import *
from oidc_provider import settings

from django.db.models import Max
 
def create_client(redirect_uris=None, name=None, response_type = 'code'):
    client = Client()
    client._redirect_uris = redirect_uris
    client.response_type = response_type    
    client.name = name
    client.client_id = uuid.uuid4().hex
    client.client_secret = uuid.uuid4().hex
    
    return client
    
    

