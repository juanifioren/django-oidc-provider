import base64, hashlib, json, struct

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import importKey

SUPPORT_ALGS = ['HS256', 'RS256']

HAS_JWKEST = HAS_JOSE = False

def long_to_base64(n):
    _bytes = []
    while n:
        n, r = divmod(n, 256)
        _bytes.append(r)
    _bytes.reverse()
    data = struct.pack('%sB' % len(_bytes), *_bytes)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s.decode("ascii")

class AdapterBase(object):
    def sign_payload(self, alg, keys, payload):
        if alg == 'RS256':
            keys = self.from_model_keys(keys)
        elif alg == 'HS256':
            keys = [self.from_client_secret(keys[0])]
        else:
            raise ValueError("Unsupported algorithm %s" % alg)

        return self._sign(alg, keys, payload)

    def generate_key(self, bits):
        key = RSA.generate(bits)
        return key.exportKey('PEM').decode('utf8')

    def to_public_key(self, rsa_key):
        return {
            'kty': 'RSA',
            'alg': 'RS256',
            'use': 'sig',
            'kid': self.get_kid(rsa_key),
            'n': long_to_base64(rsa_key.n),
            'e': long_to_base64(rsa_key.e)
        }

class JwkestAdapter(AdapterBase):
    def load_keys(self, public_keys):
        jwkest_keys = jwkest.jwk.KEYS()
        jwkest_keys.load_dict(public_keys)
        return jwkest_keys

    def from_model_keys(self, model_keys):
        return [jwkest.jwk.RSAKey(key=importKey(model_key.key), kid=model_key.kid)
            for model_key in model_keys]

    def from_client_secret(self, secret, alg):
        return jwkest.jwk.SYMKey(key=secret, alg=alg)

    def get_kid(self, rsa_key):
        return rsa_key.kid

    def _sign(self, alg, keys, payload):
        _jws = jwkest.jws.JWS(payload, alg=alg)
        return _jws.sign_compact(keys)

    def unpack_payload(self, message):
        return jwkest.jwt.JWT().unpack(message.encode('utf-8')).payload()

    def verify_payload(self, message, keys):
        return jwkest.jws.JWS().verify_compact(message.encode('utf-8'), keys)

class JoseAdapter(AdapterBase):
    def load_keys(self, public_keys):
        return [key[0] for key in public_keys.values()]

    def from_model_keys(self, model_keys):
        return [importKey(model_key.key) for model_key in model_keys]

    def from_client_secret(self, secret, alg):
        return secret

    def get_kid(self, rsa_key):
        pem = rsa_key.exportKey('PEM')
        return hashlib.md5(pem).hexdigest()

    def _sign(self, alg, keys, payload):
        return jose.jwt.encode(payload, keys[0], algorithm=alg)

    def unpack_payload(self, message):
        parts = jose.jws._load(message.encode('utf-8'))
        if not len(parts) == 4:
            raise ValueError("jose jws._load has changed")
        return json.loads(parts[1])

    def verify_payload(self, message, keys):
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

try:
    import jwkest.jwk
    import jwkest.jws
    import jwkest.jwt

    HAS_JWKEST = True

    adapter = JwkestAdapter()

except ImportError:
    import jose.jws
    import jose.jwt

    HAS_JOSE = True
    adapter = JoseAdapter()

except ImportError:
    raise ImportError("Either python-jose or pyjwkest is required.")
