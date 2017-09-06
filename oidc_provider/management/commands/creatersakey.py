from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from django.core.management.base import BaseCommand

from oidc_provider.models import RSAKey


class Command(BaseCommand):
    help = 'Randomly generate a new RSA key for the OpenID server'

    def handle(self, *args, **options):
        try:
            key = generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            rsakey = RSAKey(
                key=key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()).decode('utf8'))
            rsakey.save()
            self.stdout.write(u'RSA key successfully created with kid: {0}'.format(rsakey.kid))
        except Exception as e:
            self.stdout.write('Something goes wrong: {0}'.format(e))
