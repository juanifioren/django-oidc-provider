from datetime import timedelta
import time
import uuid

import hashlib
from Cryptodome.PublicKey.RSA import importKey
from django.utils import dateformat, timezone
from django.utils.encoding import force_text
from jwkest.jwk import RSAKey as jwk_RSAKey
from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from jwkest.jwt import JWT

from oidc_provider.lib.utils.common import get_issuer, run_processing_hook
from oidc_provider.lib.claims import StandardScopeClaims
from oidc_provider.models import (
    Code,
    RSAKey,
    Token,
)
from oidc_provider import settings


def create_id_token(token, user, aud, nonce='', at_hash='', request=None, scope=None):
    """
    Creates the id_token dictionary.
    See: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    Return a dic.
    """
    if scope is None:
        scope = []
    sub = settings.get('OIDC_IDTOKEN_SUB_GENERATOR', import_str=True)(user=user)

    expires_in = settings.get('OIDC_IDTOKEN_EXPIRE')

    # Convert datetimes into timestamps.
    now = int(time.time())
    iat_time = now
    exp_time = int(now + expires_in)
    user_auth_time = user.last_login or user.date_joined
    auth_time = int(dateformat.format(user_auth_time, 'U'))

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

    # Inlude (or not) user standard claims in the id_token.
    if settings.get('OIDC_IDTOKEN_INCLUDE_CLAIMS'):
        standard_claims = StandardScopeClaims(token)
        dic.update(standard_claims.create_response_dic())
        if settings.get('OIDC_EXTRA_SCOPE_CLAIMS'):
            custom_claims = settings.get('OIDC_EXTRA_SCOPE_CLAIMS', import_str=True)(token)
            dic.update(custom_claims.create_response_dic())

    dic = run_processing_hook(
        dic, 'OIDC_IDTOKEN_PROCESSING_HOOK',
        user=user, token=token, request=request)

    return dic


def encode_id_token(payload, client):
    """
    Represent the ID Token as a JSON Web Token (JWT).
    Return a hash.
    """
    keys = get_client_alg_keys(client)
    _jws = JWS(payload, alg=client.jwt_alg)
    return _jws.sign_compact(keys)


def decode_id_token(token, client):
    """
    Represent the ID Token as a JSON Web Token (JWT).
    Return a hash.
    """
    keys = get_client_alg_keys(client)
    return JWS().verify_compact(token, keys=keys)


def client_id_from_id_token(id_token):
    """
    Extracts the client id from a JSON Web Token (JWT).
    Returns a string or None.
    """
    payload = JWT().unpack(id_token).payload()
    aud = payload.get('aud', None)
    if aud is None:
        return None
    if isinstance(aud, list):
        return aud[0]
    return aud


def hash_token(token):
    """
    returns the sha256 hash of the token
    """
    return force_text(hashlib.sha256(token.encode('ascii')).hexdigest())


def default_create_token(
        user, client, scope, expires_at, access_token, refresh_token,
        id_token_dic, code, old_token, request, hash_token_function):
    """
    WARNING: The api of this function is still experimental and may change at any time.

    Create and populate a Token object.
    Return a saved Token object.
    It is safe to replace `access_token` and `refresh_token` here, if you want to customize them.
    You could, for example, generate a JWT instead of just a random string.
    `code` is set if this token is being created as "code response".
    `old_token` is set if this is a token refresh.
    """
    token = Token(
        user=user,
        client=client,
        expires_at=expires_at,
        scope=scope,
        access_token_hash=hash_token_function(access_token),
        access_token=access_token,
        refresh_token_hash=hash_token_function(refresh_token),
        refresh_token=refresh_token,
    )

    # TODO: Use a field that transparently handles the dict->json conversion,
    #       so that this user replaceable code gets simpler here for
    #       `id_token_dic` and `scope`. A custom field might even work for
    #       `access_token_hash` and `refresh_token_hash`.
    if id_token_dic is not None:
        token.id_token = id_token_dic
    token.scope = scope
    token.save()
    return token


def create_token(*args, **kwargs):
    kwargs['access_token'] = uuid.uuid4().hex
    kwargs['refresh_token'] = uuid.uuid4().hex
    kwargs['expires_at'] = timezone.now() + timedelta(
        seconds=settings.get('OIDC_TOKEN_EXPIRE'))
    kwargs['id_token_dic'] = kwargs.get('id_token_dic', None)
    kwargs['code'] = kwargs.get('code', None)
    kwargs['old_token'] = kwargs.get('old_token', None)
    kwargs['hash_token_function'] = hash_token
    return settings.get('OIDC_CREATE_TOKEN', import_str=True)(*args, **kwargs)


def default_create_code(
        user, client, scope, nonce, is_authentication, code, expires_at, code_challenge,
        code_challenge_method, request):
    """
    WARNING: The api of this function is still experimental and may change at any time.
    Create and populate a Code object.
    Return a saved Code object.
    """
    code = Code(
        user=user,
        client=client,
        code=code,
        expires_at=expires_at,
        scope=scope,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        is_authentication=is_authentication,
    )
    # TODO: Use a field that transparently handles the dict->json conversion,
    #       so that this user replaceable code gets simpler here for `scope`.
    code.scope = scope
    code.save()
    return code


def create_code(*args, **kwargs):
    code_challenge = kwargs.get('code_challenge', None)
    code_challenge_method = kwargs.get('code_challenge_method', None)
    if not (code_challenge and code_challenge_method):
        code_challenge = code_challenge_method = None
    kwargs['code_challenge'] = code_challenge
    kwargs['code_challenge_method'] = code_challenge_method

    kwargs['expires_at'] = timezone.now() + timedelta(
        seconds=settings.get('OIDC_CODE_EXPIRE'))

    kwargs['code'] = uuid.uuid4().hex
    return settings.get('OIDC_CREATE_CODE', import_str=True)(*args, **kwargs)


def get_client_alg_keys(client):
    """
    Takes a client and returns the set of keys associated with it.
    Returns a list of keys.
    """
    if client.jwt_alg == 'RS256':
        keys = []
        for rsakey in RSAKey.objects.all():
            keys.append(jwk_RSAKey(key=importKey(rsakey.key), kid=rsakey.kid))
        if not keys:
            raise Exception('You must add at least one RSA Key.')
    elif client.jwt_alg == 'HS256':
        keys = [SYMKey(key=client.client_secret, alg=client.jwt_alg)]
    else:
        raise Exception('Unsupported key algorithm.')

    return keys


def _get_token(raw_token, fieldname, client=None):
    qs = Token.objects.all()
    if client:
        qs = qs.filter(client=client)
    hash_fieldname = '{}_hash'.format(fieldname)
    hashed_token = hash_token(raw_token)
    token = qs.get(**{hash_fieldname: hashed_token})
    if getattr(token, fieldname) != raw_token:
        # Suspicious. Bad hash in database or hash collision attack.
        raise Token.DoesNotExist(
            "%s matching query does not exist." %
            Token._meta.object_name
        )
    return token


def get_by_access_token(access_token, client=None):
    return _get_token(raw_token=access_token, fieldname='access_token', client=client)


def get_by_refresh_token(refresh_token, client=None):
    return _get_token(raw_token=refresh_token, fieldname='refresh_token', client=client)


def default_get_valid_refresh_token(refresh_token, client, request):
    return get_by_refresh_token(refresh_token=refresh_token, client=client)


def get_valid_refresh_token(**kwargs):
    return settings.get('OIDC_GET_VALID_REFRESH_TOKEN', import_str=True)(**kwargs)
