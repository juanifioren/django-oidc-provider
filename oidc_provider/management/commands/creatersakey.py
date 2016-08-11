import os

from django.core.management.base import BaseCommand

from oidc_provider.lib.jwt_compat import adapter
from oidc_provider import settings
from oidc_provider.models import RSAKey


class Command(BaseCommand):
    help = 'Randomly generate a new RSA key for the OpenID server'

    def handle(self, *args, **options):
        try:
            rsakey = RSAKey(key=adapter.generate_key(1024).decode('utf-8'))
            rsakey.save()
            self.stdout.write(u'RSA key successfully created with kid: {0}'.format(rsakey.kid))
        except Exception as e:
            self.stdout.write('Something goes wrong: {0}'.format(e))
