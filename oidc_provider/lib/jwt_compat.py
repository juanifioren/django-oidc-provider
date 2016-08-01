import hashlib, json

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import importKey

SUPPORT_ALGS = ['HS256', 'RS256']

HAS_JWKEST = HAS_JOSE = False
try:
    import jwkest.jwk
    import jwkest.jws
    import jwkest.jwt

    HAS_JWKEST = True

    def load_keys(public_keys):
        jwkest_keys = jwkest.jwk.KEYS()
        jwkest_keys.load_dict(public_keys)
        return jwkest_keys

    def from_model_keys(model_keys):
        return [jwkest.jwk.RSAKey(key=importKey(model_key.key), kid=model_key.kid)
            for model_key in model_keys]

    def from_client_secret(secret, alg):
        return jwkest.jwk.SYMKey(key=secret, alg=alg)

    def get_kid(rsa_key):
        return rsa_key.kid
except ImportError:
    import jose.jws
    import jose.jwt

    HAS_JOSE = True

    def load_keys(public_keys):
        return [key[0] for key in public_keys.values()]

    def from_model_keys(model_keys):
        return [importKey(model_key.key) for model_key in model_keys]

    def from_client_secret(secret, alg):
        return secret

    def get_kid(rsa_key):
        pem = rsa_key.exportKey('PEM')
        return hashlib.md5(pem).hexdigest()

except ImportError:
    raise ImportError("Either python-jose or pyjwkest is required.")

from oidc_provider.lib.utils.common import long_to_base64

def generate_key(bits):
    key = RSA.generate(bits)
    return key.exportKey('PEM').decode('utf8')

def to_public_key(rsa_key):
    return {
        'kty': 'RSA',
        'alg': 'RS256',
        'use': 'sig',
        'kid': get_kid(rsa_key),
        'n': long_to_base64(rsa_key.n),
        'e': long_to_base64(rsa_key.e)
    }

def sign_payload(alg, keys, payload):
    if alg == 'RS256':
        keys = from_model_keys(keys)
    elif alg == 'HS256':
        keys = [from_client_secret(keys[0])]
    else:
        raise ValueError("Unsupported algorithm %s" % alg)

    if HAS_JWKEST:
        _jws = jwkest.jws.JWS(payload, alg=alg)
        return _jws.sign_compact(keys)
    else: # has jose
        return jose.jwt.encode(payload, keys[0], algorithm=alg)

def unpack_payload(message):
    if HAS_JWKEST:
        return jwkest.jwt.JWT().unpack(message.encode('utf-8')).payload()
    else:
        parts = jose.jws._load(message.encode('utf-8'))
        if not len(parts) == 4:
            raise ValueError("jose jws._load has changed")
        return json.loads(parts[1])

def verify_payload(message, keys):
    if HAS_JWKEST:
        return jwkest.jws.JWS().verify_compact(message.encode('utf-8'), keys)
    else:
        for key in keys:
            try:
                payload = jose.jws.verify(message, key, SUPPORT_ALGS)
            except jose.JWSError:
                pass
            try:
                return json.loads(payload)
            except ValueError:
                raise JWSError("Non-JSON payload")
        else:
            raise JWSError('Signature verification failed.')

