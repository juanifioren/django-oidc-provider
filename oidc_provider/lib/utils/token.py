from datetime import timedelta
import time
import uuid

from django.utils import timezone
import jwt

from oidc_provider.lib.utils.common import get_issuer
from oidc_provider.models import *
from oidc_provider import settings


def create_id_token(user, aud):
    """
    Receives a user object and aud (audience).
    Then creates the id_token dictionary.
    See: http://openid.net/specs/openid-connect-core-1_0.html#IDToken

    Return a dic.
    """
    sub = settings.get('OIDC_IDTOKEN_SUB_GENERATOR')(
        user=user)

    expires_in = settings.get('OIDC_IDTOKEN_EXPIRE')

    now = timezone.now()
    # Convert datetimes into timestamps.
    iat_time = time.mktime(now.timetuple())
    exp_time = time.mktime((now + timedelta(seconds=expires_in)).timetuple())

    user_auth_time = user.last_login or user.date_joined
    auth_time = time.mktime(user_auth_time.timetuple())

    dic = {
        'iss': get_issuer(),
        'sub': sub,
        'aud': aud,
        'exp': exp_time,
        'iat': iat_time,
        'auth_time': auth_time,
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


def create_code(user, client, scope):
    """
    Create and populate a Code object.

    Return a Code object.
    """
    code = Code()
    code.user = user
    code.client = client
    code.code = uuid.uuid4().hex
    code.expires_at = timezone.now() + timedelta(
        seconds=settings.get('OIDC_CODE_EXPIRE'))
    code.scope = scope

    return code