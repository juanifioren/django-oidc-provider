import os
from Crypto.PublicKey import RSA

from oidc_provider import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Randomly generate a new RSA key for the OpenID server'

    def handle(self, *args, **options):
        try:
            key = RSA.generate(1024)
            file_path = os.path.join(settings.get('OIDC_RSA_KEY_FOLDER'), 'OIDC_RSA_KEY.pem')
            with open(file_path, 'wb') as f:
                f.write(key.exportKey('PEM'))
            self.stdout.write('RSA key successfully created at: ' + file_path)
        except Exception as e:
            self.stdout.write('Something goes wrong: {0}'.format(e))
