import json

from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.conf import settings


class Client(models.Model):

    RESPONSE_TYPE_CHOICES = [
        ('code', 'code (Authorization Code Flow)'),
        ('id_token', 'id_token (Implicit Flow)'),
        ('id_token token', 'id_token token (Implicit Flow)'),
    ]

    name = models.CharField(max_length=100, default='')
    client_id = models.CharField(max_length=255, unique=True)
    client_secret = models.CharField(max_length=255, unique=True)
    response_type = models.CharField(max_length=30,
                                     choices=RESPONSE_TYPE_CHOICES)
    date_created = models.DateField(auto_now_add=True)

    _redirect_uris = models.TextField(default='', verbose_name=_(u'Redirect URI'), help_text=_(u'Enter each URI on a new line.'))

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

    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    client = models.ForeignKey(Client)
    expires_at = models.DateTimeField()
    _scope = models.TextField(default='')

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
        return u'{0} - {1} ({2})'.format(self.client, self.user.email, self.expires_at)

    def __unicode__(self):
        return self.__str__()
    
    class Meta:
        abstract = True


class Code(BaseCodeTokenModel):

    code = models.CharField(max_length=255, unique=True)
    nonce = models.CharField(max_length=255, blank=True, default='')

    class Meta:
        verbose_name = _(u'Authorization Code')
        verbose_name_plural = _(u'Authorization Codes')


class Token(BaseCodeTokenModel):

    access_token = models.CharField(max_length=255, unique=True)
    refresh_token = models.CharField(max_length=255, unique=True, null=True)
    _id_token = models.TextField()
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


class UserConsent(BaseCodeTokenModel):

    class Meta:
        unique_together = ('user', 'client')
