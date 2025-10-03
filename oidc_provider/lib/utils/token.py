import time
import uuid
from datetime import timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from django.utils import dateformat
from django.utils import timezone

from oidc_provider import settings
from oidc_provider.lib.claims import StandardScopeClaims
from oidc_provider.lib.utils.common import get_issuer
from oidc_provider.lib.utils.common import run_processing_hook
from oidc_provider.models import Code
from oidc_provider.models import RSAKey
from oidc_provider.models import Token

# Cache for loaded RSA keys to avoid repeated PEM parsing
# Cache is automatically cleaned of stale entries (keys no longer in DB)
_rsa_key_cache = {}


def create_id_token(token, user, aud, nonce="", at_hash="", request=None, scope=None):
    """
    Creates the id_token dictionary.
    See: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    Return a dic.
    """
    if scope is None:
        scope = []
    sub = settings.get("OIDC_IDTOKEN_SUB_GENERATOR", import_str=True)(user=user)

    expires_in = settings.get("OIDC_IDTOKEN_EXPIRE")

    # Convert datetimes into timestamps.
    now = int(time.time())
    iat_time = now
    exp_time = int(now + expires_in)
    user_auth_time = user.last_login or user.date_joined
    auth_time = int(dateformat.format(user_auth_time, "U"))

    dic = {
        "iss": get_issuer(request=request),
        "sub": sub,
        "aud": str(aud),
        "exp": exp_time,
        "iat": iat_time,
        "auth_time": auth_time,
    }

    if nonce:
        dic["nonce"] = str(nonce)

    if at_hash:
        dic["at_hash"] = at_hash

    # Inlude (or not) user standard claims in the id_token.
    if settings.get("OIDC_IDTOKEN_INCLUDE_CLAIMS"):
        standard_claims = StandardScopeClaims(token)
        dic.update(standard_claims.create_response_dic())

        if settings.get("OIDC_EXTRA_SCOPE_CLAIMS"):
            extra_claims = settings.get("OIDC_EXTRA_SCOPE_CLAIMS", import_str=True)(token)
            dic.update(extra_claims.create_response_dic())

    dic = run_processing_hook(
        dic, "OIDC_IDTOKEN_PROCESSING_HOOK", user=user, token=token, request=request
    )

    return dic


def encode_id_token(payload, client):
    """
    Represent the ID Token as a JSON Web Token (JWT).
    Returns a dict.
    """
    keys = get_client_alg_keys(client)
    # Use the first key for encoding
    # TODO: make key selection more explicit
    key_info = keys[0]

    headers = {}
    if "kid" in key_info:
        headers["kid"] = key_info["kid"]

    return jwt.encode(payload, key_info["key"], algorithm=key_info["algorithm"], headers=headers)


def decode_id_token(token, client):
    """
    Represent the ID Token as a JSON Web Token (JWT).
    Returns a dict.
    """
    # Try decoding with each available key
    for key in get_client_alg_keys(client):
        try:
            return jwt.decode(
                jwt=token,
                # HS256 uses the same key for signing and verifying
                key=key["key"] if key["algorithm"] == "HS256" else key["public_key"],
                algorithms=[key["algorithm"]],
                options={
                    "verify_signature": True,
                    "verify_aud": False,  # Disable audience validation for compatibility
                    "verify_exp": False,  # Disable expiration validation for compatibility
                    "verify_iat": False,  # Disable issued at validation for compatibility
                    "verify_nbf": False,  # Disable not before validation for compatibility
                },
            )
        except jwt.InvalidTokenError:
            continue

    # If we get here, none of the keys worked
    raise jwt.InvalidTokenError("Token could not be decoded with any available key")


def client_id_from_id_token(id_token):
    """
    Extracts the client id from a JSON Web Token (JWT).
    Does NOT verify the token signature or expiration.
    Returns a string or None.
    """
    # Decode without verification to get the payload
    payload = jwt.decode(id_token, options={"verify_signature": False})
    aud = payload.get("aud", None)
    if aud is None:
        return None
    if isinstance(aud, list):
        return aud[0]
    return aud


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
    token.expires_at = timezone.now() + timedelta(seconds=settings.get("OIDC_TOKEN_EXPIRE"))
    token.scope = scope

    return token


def create_code(
    user, client, scope, nonce, is_authentication, code_challenge=None, code_challenge_method=None
):
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

    code.expires_at = timezone.now() + timedelta(seconds=settings.get("OIDC_CODE_EXPIRE"))
    code.scope = scope
    code.nonce = nonce
    code.is_authentication = is_authentication

    return code


def get_client_alg_keys(client):
    """
    Takes a client and returns the set of keys associated with it.
    Returns a list of keys compatible with PyJWT.
    """
    if client.jwt_alg == "RS256":
        keys = []
        current_kids = set()

        for rsakey in RSAKey.objects.all():
            cache_key = f"rsa_key_{rsakey.kid}"
            current_kids.add(cache_key)

            if cache_key not in _rsa_key_cache:
                # Load the RSA private key using cryptography (expensive operation)
                private_key = serialization.load_pem_private_key(
                    rsakey.key.encode("utf-8"),
                    password=None,
                )
                # Also cache the public key to avoid repeated .public_key() calls
                public_key = private_key.public_key()
                _rsa_key_cache[cache_key] = {"private_key": private_key, "public_key": public_key}

            key_pair = _rsa_key_cache[cache_key]
            keys.append(
                {
                    "key": key_pair["private_key"],
                    "public_key": key_pair["public_key"],
                    "kid": rsakey.kid,
                    "algorithm": "RS256",
                }
            )

        # Clean up stale cache entries (keys that no longer exist in DB)
        stale_keys = set(_rsa_key_cache.keys()) - current_kids
        for stale_key in stale_keys:
            del _rsa_key_cache[stale_key]

        if not keys:
            raise Exception("You must add at least one RSA Key.")
    elif client.jwt_alg == "HS256":
        # NOTE: HS256 does not have any expensive key parsing, so we don't need the
        #       same key caching as RS256.
        keys = [{"key": client.client_secret, "algorithm": "HS256"}]
    else:
        raise Exception("Unsupported key algorithm.")

    return keys
