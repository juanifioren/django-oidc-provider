from datetime import timedelta
import time
import uuid

from Cryptodome.PublicKey.RSA import importKey
from django.utils import timezone
from jwkest.jwk import RSAKey as jwk_RSAKey
from jwkest.jwk import SYMKey
from jwkest.jws import JWS

from oidc_provider.lib.utils.common import get_issuer
from oidc_provider.models import (
    Code,
    RSAKey,
    Token,
)
from oidc_provider import settings


def create_id_token(user, aud, nonce, at_hash=None, request=None, scope=[]):
    """
    Creates the id_token dictionary.
    See: http://openid.net/specs/openid-connect-core-1_0.html#IDToken

    Return a dic.
    """
    sub = settings.get('OIDC_IDTOKEN_SUB_GENERATOR', import_str=True)(user=user)

    expires_in = settings.get('OIDC_IDTOKEN_EXPIRE')

    # Convert datetimes into timestamps.
    now = timezone.now()
    iat_time = int(time.mktime(now.timetuple()))
    exp_time = int(time.mktime((now + timedelta(seconds=expires_in)).timetuple()))
    user_auth_time = user.last_login or user.date_joined
    auth_time = int(time.mktime(user_auth_time.timetuple()))

    dic = {
        'iss': get_issuer(request=request),
        'sub': sub,
        'aud': str(aud),
        'exp': exp_time,
        'iat': iat_time,
        'auth_time': auth_time,
    }

    if nonce:
        dic['nonce'] = str(nonce)

    if at_hash:
        dic['at_hash'] = at_hash

    if ('email' in scope) and getattr(user, 'email', None):
        dic['email'] = user.email

    processing_hook = settings.get('OIDC_IDTOKEN_PROCESSING_HOOK')

    if isinstance(processing_hook, (list, tuple)):
        for hook in processing_hook:
            dic = settings.import_from_str(hook)(dic, user=user)
    else:
        dic = settings.import_from_str(processing_hook)(dic, user=user)

    return dic


def encode_id_token(payload, client):
    """
    Represent the ID Token as a JSON Web Token (JWT).

    Return a hash.
    """
    alg = client.jwt_alg
    if alg == 'RS256':
        keys = []
        for rsakey in RSAKey.objects.all():
            keys.append(jwk_RSAKey(key=importKey(rsakey.key), kid=rsakey.kid))

        if not keys:
            raise Exception('You must add at least one RSA Key.')
    elif alg == 'HS256':
        keys = [SYMKey(key=client.client_secret, alg=alg)]
    else:
        raise Exception('Unsupported key algorithm.')

    _jws = JWS(payload, alg=alg)

    return _jws.sign_compact(keys)


def create_token(user, client, scope, id_token_dic=None):
    """
    Create and populate a Token object.

    Return a Token object.
    """
    token = Token()
    token.user = user
    token.client = client
    token.access_token = uuid.uuid4().hex

    if id_token_dic is not None:
        token.id_token = id_token_dic

    token.refresh_token = uuid.uuid4().hex
    token.expires_at = timezone.now() + timedelta(
        seconds=settings.get('OIDC_TOKEN_EXPIRE'))
    token.scope = scope

    return token


def create_code(user, client, scope, nonce, is_authentication,
                code_challenge=None, code_challenge_method=None):
    """
    Create and populate a Code object.

    Return a Code object.
    """
    code = Code()
    code.user = user
    code.client = client

    code.code = uuid.uuid4().hex

    if code_challenge and code_challenge_method:
        code.code_challenge = code_challenge
        code.code_challenge_method = code_challenge_method

    code.expires_at = timezone.now() + timedelta(
        seconds=settings.get('OIDC_CODE_EXPIRE'))
    code.scope = scope
    code.nonce = nonce
    code.is_authentication = is_authentication

    return code
