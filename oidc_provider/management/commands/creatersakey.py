from Crypto.PublicKey import RSA

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Randomly generate a new RSA key for the OpenID server'

    def handle(self, *args, **options):
        try:
            key = RSA.generate(1024)
            file_path = settings.BASE_DIR + '/OIDC_RSA_KEY.pem'
            with open(file_path, 'w') as f:
                f.write(key.exportKey('PEM'))
            self.stdout.write('RSA key successfully created at: ' + file_path)
        except Exception as e:
            self.stdout.write('Something goes wrong: ' + e.message)
