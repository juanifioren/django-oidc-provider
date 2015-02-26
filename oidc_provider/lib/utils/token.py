from datetime import timedelta
from django.utils import timezone
from oidc_provider.models import *
from oidc_provider import settings
import jwt
import time
import uuid


def create_id_token_dic(user, iss, aud):
    """
    Receives a user object, iss (issuer) and aud (audience).
    Then creates the id_token dic.
    See: http://openid.net/specs/openid-connect-core-1_0.html#IDToken

    Return a dic.
    """
    expires_in = settings.get('OIDC_IDTOKEN_EXPIRE')

    now = timezone.now()

    # Convert datetimes into timestamps.
    iat_time = time.mktime(now.timetuple())
    exp_time = time.mktime((now + timedelta(seconds=expires_in)).timetuple())
    user_auth_time = time.mktime(user.last_login.timetuple())

    dic = {
        'iss': iss,
        'sub': user.id,
        'aud': aud,
        'exp': exp_time,
        'iat': iat_time,
        'auth_time': user_auth_time,
    }

    return dic


def encode_id_token(id_token_dic, client_secret):
    """
    Represent the ID Token as a JSON Web Token (JWT).

    Return a hash.
    """
    id_token_hash = jwt.encode(id_token_dic, client_secret)

    return id_token_hash


def create_token(user, client, id_token_dic, scope):
    """
    Create and populate a Token object.

    Return a Token object.
    """
    token = Token()
    token.user = user
    token.client = client
    token.access_token = uuid.uuid4().hex

    token.id_token = id_token_dic

    token.refresh_token = uuid.uuid4().hex
    token.expires_at = timezone.now() + timedelta(
        seconds=settings.get('OIDC_TOKEN_EXPIRE'))
    token.scope = scope

    return token
