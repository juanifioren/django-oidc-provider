# -*- coding: utf-8 -*-
import base64
import binascii
from hashlib import md5, sha256
import json

from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.conf import settings


CLIENT_TYPE_CHOICES = [
    ('confidential', 'Confidential'),
    ('public', 'Public'),
]

RESPONSE_TYPE_CHOICES = [
    ('code', 'code (Authorization Code Flow)'),
    ('id_token', 'id_token (Implicit Flow)'),
    ('id_token token', 'id_token token (Implicit Flow)'),
    ('code token', 'code token (Hybrid Flow)'),
    ('code id_token', 'code id_token (Hybrid Flow)'),
    ('code id_token token', 'code id_token token (Hybrid Flow)'),
]

JWT_ALGS = [
    ('HS256', 'HS256'),
    ('RS256', 'RS256'),
]


class Client(models.Model):

    name = models.CharField(max_length=100, default='', verbose_name=_(u'Name'))
    client_type = models.CharField(max_length=30, choices=CLIENT_TYPE_CHOICES, default='confidential', verbose_name=_(u'Client Type'), help_text=_(u'<b>Confidential</b> clients are capable of maintaining the confidentiality of their credentials. <b>Public</b> clients are incapable.'))
    client_id = models.CharField(max_length=255, unique=True, verbose_name=_(u'Client ID'))
    client_secret = models.CharField(max_length=255, blank=True, verbose_name=_(u'Client SECRET'))
    response_type = models.CharField(max_length=30, choices=RESPONSE_TYPE_CHOICES, verbose_name=_(u'Response Type'))
    jwt_alg = models.CharField(max_length=10, choices=JWT_ALGS, default='RS256', verbose_name=_(u'JWT Algorithm'), help_text=_(u'Algorithm used to encode ID Tokens.'))
    date_created = models.DateField(auto_now_add=True, verbose_name=_(u'Date Created'))
    website_url = models.CharField(max_length=255, blank=True, default='', verbose_name=_(u'Website URL'))
    terms_url = models.CharField(max_length=255, blank=True, default='', verbose_name=_(u'Terms URL'), help_text=_(u'External reference to the privacy policy of the client.'))
    contact_email = models.CharField(max_length=255, blank=True, default='', verbose_name=_(u'Contact Email'))
    logo = models.FileField(blank=True, default='', upload_to='oidc_provider/clients', verbose_name=_(u'Logo Image'))

    _redirect_uris = models.TextField(default='', verbose_name=_(u'Redirect URIs'), help_text=_(u'Enter each URI on a new line.'))

    class Meta:
        verbose_name = _(u'Client')
        verbose_name_plural = _(u'Clients')

    def __str__(self):
        return u'{0}'.format(self.name)

    def __unicode__(self):
        return self.__str__()

    def redirect_uris():
        def fget(self):
            return self._redirect_uris.splitlines()

        def fset(self, value):
            self._redirect_uris = '\n'.join(value)

        return locals()
    redirect_uris = property(**redirect_uris())

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0] if self.redirect_uris else ''


class BaseCodeTokenModel(models.Model):

    user = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_(u'User'))
    client = models.ForeignKey(Client, verbose_name=_(u'Client'))
    expires_at = models.DateTimeField(verbose_name=_(u'Expiration Date'))
    _scope = models.TextField(default='', verbose_name=_(u'Scopes'))

    def scope():
        def fget(self):
            return self._scope.split()

        def fset(self, value):
            self._scope = ' '.join(value)

        return locals()
    scope = property(**scope())

    def has_expired(self):
        return timezone.now() >= self.expires_at

    def __str__(self):
        return u'{0} - {1}'.format(self.client, self.user.email)

    def __unicode__(self):
        return self.__str__()

    class Meta:
        abstract = True


class Code(BaseCodeTokenModel):

    code = models.CharField(max_length=255, unique=True, verbose_name=_(u'Code'))
    nonce = models.CharField(max_length=255, blank=True, default='', verbose_name=_(u'Nonce'))
    is_authentication = models.BooleanField(default=False, verbose_name=_(u'Is Authentication?'))
    code_challenge = models.CharField(max_length=255, null=True, verbose_name=_(u'Code Challenge'))
    code_challenge_method = models.CharField(max_length=255, null=True, verbose_name=_(u'Code Challenge Method'))

    class Meta:
        verbose_name = _(u'Authorization Code')
        verbose_name_plural = _(u'Authorization Codes')


class Token(BaseCodeTokenModel):

    access_token = models.CharField(max_length=255, unique=True, verbose_name=_(u'Access Token'))
    refresh_token = models.CharField(max_length=255, unique=True, null=True, verbose_name=_(u'Refresh Token'))
    _id_token = models.TextField(verbose_name=_(u'ID Token'))

    def id_token():

        def fget(self):
            return json.loads(self._id_token)

        def fset(self, value):
            self._id_token = json.dumps(value)

        return locals()
    id_token = property(**id_token())

    class Meta:
        verbose_name = _(u'Token')
        verbose_name_plural = _(u'Tokens')

    @property
    def at_hash(self):
        # @@@ d-o-p only supports 256 bits (change this if that changes)
        hashed_access_token = sha256(
            self.access_token.encode('ascii')
        ).hexdigest().encode('ascii')
        return base64.urlsafe_b64encode(
            binascii.unhexlify(
                hashed_access_token[:len(hashed_access_token) // 2]
            )
        ).rstrip(b'=').decode('ascii')


class UserConsent(BaseCodeTokenModel):

    date_given = models.DateTimeField(verbose_name=_(u'Date Given'))

    class Meta:
        unique_together = ('user', 'client')


class RSAKey(models.Model):

    key = models.TextField(verbose_name=_(u'Key'), help_text=_(u'Paste your private RSA Key here.'))

    class Meta:
        verbose_name = _(u'RSA Key')
        verbose_name_plural = _(u'RSA Keys')

    def __str__(self):
        return u'{0}'.format(self.kid)

    def __unicode__(self):
        return self.__str__()

    @property
    def kid(self):
        return u'{0}'.format(md5(self.key.encode('utf-8')).hexdigest() if self.key else '')
