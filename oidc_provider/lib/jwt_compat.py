from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import importKey
from jwkest.jwk import KEYS
from jwkest.jwk import RSAKey as jwk_RSAKey
from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from jwkest.jwt import JWT
from jwkest import long_to_base64 as l_to_b64

def generate_key(bits):
    key = RSA.generate(bits)
    return key.exportKey('PEM').decode('utf8')

def load_keys(public_keys):
    SIGKEYS = KEYS()
    SIGKEYS.load_dict(public_keys)
    return SIGKEYS

def to_rsa_keys(model_keys):
    return [jwk_RSAKey(key=importKey(model_key.key), kid=model_key.kid)
        for model_key in model_keys]

def to_public_key(rsa_key):
    return {
        'kty': 'RSA',
        'alg': 'RS256',
        'use': 'sig',
        'kid': rsa_key.kid,
        'n': long_to_base64(rsa_key.n),
        'e': long_to_base64(rsa_key.e)
    }

def sign_payload(alg, keys, payload):
    if alg == 'RS256':
        keys = to_rsa_keys(keys)
    elif alg == 'HS256':
        keys = [SYMKey(key=keys[0], alg=alg)]

    _jws = JWS(payload, alg=alg)

    return _jws.sign_compact(keys)

def unpack_payload(message):
    return JWT().unpack(message.encode('utf-8')).payload()

def verify_payload(message, keys):
    return JWS().verify_compact(message.encode('utf-8'), keys)

def long_to_base64(n):
    return l_to_b64(n)
