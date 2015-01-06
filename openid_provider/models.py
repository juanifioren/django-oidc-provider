from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
import json


class Client(models.Model):

    CLIENT_TYPE_CHOICES = [
        ('confidential', 'Confidential'),
        #('public', 'Public'),
    ]

    GRANT_TYPE_CHOICES = [
        ('authorization_code', 'Authorization Code Flow'),
        #('implicit', 'Implicit Flow'),
    ]

    RESPONSE_TYPE_CHOICES = [
        ('code', 'Authorization Code Flow'),
        #('id_token', 'Implicit Flow'),
        #('id_token token', 'Implicit Flow'),
    ]

    name = models.CharField(max_length=100, default='')
    user = models.ForeignKey(User)
    client_id = models.CharField(max_length=255, unique=True)
    client_secret = models.CharField(max_length=255, unique=True)
    client_type = models.CharField(max_length=20, choices=CLIENT_TYPE_CHOICES)
    grant_type = models.CharField(max_length=30, choices=GRANT_TYPE_CHOICES)
    response_type = models.CharField(max_length=30, choices=RESPONSE_TYPE_CHOICES)
    
    # TODO: Need to be implemented.
    # The list of scopes the client may request access to.
    _scope = models.TextField(default='')
    def scope():
        def fget(self):
            return self._scope.split()
        def fset(self, value):
            self._scope = ' '.join(value)
        return locals()
    scope = property(**scope())

    _redirect_uris = models.TextField(default='')
    def redirect_uris():
        def fget(self):
            return self._redirect_uris.splitlines()
        def fset(self, value):
            self._redirect_uris = '\n'.join(value)
        return locals()
    redirect_uris = property(**redirect_uris())

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

class Code(models.Model):

    user = models.ForeignKey(User)
    client = models.ForeignKey(Client)
    code = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField()
    scope = models.TextField() # TODO: add getter and setter for this.

    def has_expired(self):
        return timezone.now() >= self.expires_at

class Token(models.Model):

    user = models.ForeignKey(User)
    client = models.ForeignKey(Client)
    access_token = models.CharField(max_length=255, unique=True)
    refresh_token = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField()
    scope = models.TextField() # TODO: add getter and setter for this.

    _id_token = models.TextField()
    def id_token():
        def fget(self):
            return json.loads(self._id_token)
        def fset(self, value):
            self._id_token = json.dumps(value)
        return locals()
    id_token = property(**id_token())

class UserInfo(models.Model):

    user = models.OneToOneField(User, primary_key=True)

    given_name = models.CharField(max_length=255, default='')
    family_name = models.CharField(max_length=255, default='')
    middle_name = models.CharField(max_length=255, default='')
    nickname = models.CharField(max_length=255, default='')
    preferred_username = models.CharField(max_length=255, default='')
    profile = models.URLField(default='')
    picture = models.URLField(default='')
    website = models.URLField(default='')
    email_verified = models.BooleanField(default=False)
    gender = models.CharField(max_length=100, default='')
    birthdate = models.DateField()
    zoneinfo = models.CharField(max_length=100, default='')
    locale = models.CharField(max_length=100, default='')
    phone_number = models.CharField(max_length=255, default='')
    phone_number_verified = models.BooleanField(default=False)
    address_formatted = models.CharField(max_length=255, default='')
    address_street_address = models.CharField(max_length=255, default='')
    address_locality = models.CharField(max_length=255, default='')
    address_region = models.CharField(max_length=255, default='')
    address_postal_code = models.CharField(max_length=255, default='')
    address_country = models.CharField(max_length=255, default='')
    updated_at = models.DateTimeField()

    @property
    def name(self):
        name = ''
        if self.given_name:
            name = self.given_name
            if self.family_name:
                name = name + ' ' + self.family_name

        return name