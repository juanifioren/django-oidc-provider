import secrets
from secrets import choice

from django.core.management.base import BaseCommand

from oidc_provider.models import Client, CLIENT_TYPE_CHOICES, RESPONSE_TYPE_CHOICES, JWT_ALGS

CLIENT_ID_CHARACTER_SET = (r'!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN'
                           'OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}')


class Command(BaseCommand):
    help = 'Create OAuth2 Client ID and secrets'

    def add_arguments(self, parser):
        parser.add_argument(
            '--name',
            action='store',
            dest='name',
            required=True,
            type=str,
            help='Client Name'
        )
        parser.add_argument(
            '--client-type',
            action='store',
            dest='client_type',
            default='confidential',
            type=str, choices=[client[0] for client in CLIENT_TYPE_CHOICES],
            help='Confidential clients are capable of maintaining the confidentiality of their credentials. Public clients are incapable.'
        )
        parser.add_argument(
            '--client-id',
            action='store',
            dest='client_id',
            default=''.join(choice(CLIENT_ID_CHARACTER_SET) for i in range(32)),
            type=str,
            help='Client ID',
        )
        parser.add_argument(
            '--client-secret',
            action='store',
            dest='client_secret',
            default=secrets.token_urlsafe(32),
            type=str,
            help='Client Secret',
        )
        parser.add_argument(
            '--response-type',
            action='store',
            dest='response_type',
            default='code id_token',
            type=str, choices=[response[0] for response in RESPONSE_TYPE_CHOICES],
            help='Response Type'
        )
        parser.add_argument(
            '--jwt-alg',
            action='store',
            dest='jwt_alg',
            default='RS256',
            type=str, choices=[jwt[0] for jwt in JWT_ALGS],
            help='JWT algorithm'
        )
        parser.add_argument(
            '--website-url',
            action='store',
            dest='website_url',
            default='',
            type=str,
            help='Website URL'
        )
        parser.add_argument(
            '--terms-url',
            action='store',
            dest='terms_url',
            default='',
            type=str,
            help='Terms URL'
        )
        parser.add_argument(
            '--contact-email',
            action='store',
            dest='contact_email',
            default='',
            type=str,
            help='Contact Email'
        )
        parser.add_argument(
            '--logo',
            action='store',
            dest='logo',
            default='',
            type=str,
            help='Logo Image'
        )
        parser.add_argument(
            '--redirect-uris',
            action='store',
            dest='redirect_uris',
            required=True,
            type=str,
            help='Enter each URI on a new line.'
        )
        parser.add_argument(
            '--post-logout-redirect_uris',
            action='store',
            dest='post_logout_redirect_uris',
            default='',
            type=str,
            help='Enter each URI on a new line.'
        )

    def handle(self, *args, **options):
        try:
            data = {
                'name': options['name'],
                'client_type': options['client_type'],
                'client_id': options['client_id'],
                'client_secret': options['client_secret'],
                'response_type': options['response_type'],
                'jwt_alg': options['jwt_alg'],
                'website_url': options['website_url'],
                'terms_url': options['terms_url'],
                'contact_email': options['contact_email'],
                'logo': options['logo'],
                'redirect_uris': options['redirect_uris'].split(' '),
                'post_logout_redirect_uris': options['post_logout_redirect_uris'].split(' '),
            }
            client = Client(**data)
            client.save()
            self.stdout.write(u'OAuth2 Client ID successfully created: {client.name}, {client.client_id}, {client.client_secret}, {client.redirect_uris}'.format(client=client))
        except Exception as e:
            self.stdout.write('Something goes wrong: {0}'.format(e))
