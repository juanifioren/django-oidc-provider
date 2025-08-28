from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.management.base import BaseCommand

from oidc_provider.models import RSAKey


class Command(BaseCommand):
    help = "Randomly generate a new RSA key for the OpenID server"

    def handle(self, *args, **options):
        try:
            # Generate a new RSA private key with 2048 bits
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Serialize the private key to PEM format
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            rsakey = RSAKey(key=key_pem)
            rsakey.save()
            self.stdout.write("RSA key successfully created with kid: {0}".format(rsakey.kid))
        except Exception as e:
            self.stdout.write("Something goes wrong: {0}".format(e))
