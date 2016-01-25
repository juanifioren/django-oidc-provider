# Welcome to the Docs!

Django OIDC Provider can help you providing out of the box all the endpoints, data and logic needed to add OpenID Connect capabilities to your Django projects.


**This project is still in DEVELOPMENT and is rapidly changing.**

****************************************

Before getting started there are some important things that you should know:
* Although OpenID was built on top of OAuth2, this isn't an OAuth2 server. Maybe in a future it will be.
* Despite that implementation MUST support TLS. You can make request without using SSL. There is no control on that.
* This cover `Authorization Code` flow and `Implicit` flow, NO support for `Hybrid` flow at this moment.
* Only support for requesting Claims using Scope Values.

# Table Of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Users And Clients](#users-and-clients)
- [Server RSA Keys](#rsa-keys)
- [Templates](#templates)
- [Standard Claims](#standard-claims)
- [Server Endpoints](#server-endpoints)
- [Running Tests](#running-tests)
- [Relying Parties](#relying-parties)
- [Settings](#settings)
    - [SITE_URL](#site_url)
    - [LOGIN_URL](#login_url)
    - [OIDC_AFTER_USERLOGIN_HOOK](#oidc_after_userlogin_hook)
    - [OIDC_CODE_EXPIRE](#oidc_code_expire)
    - [OIDC_EXTRA_SCOPE_CLAIMS](#oidc_extra_scope_claims)
    - [OIDC_IDTOKEN_EXPIRE](#oidc_idtoken_expire)
    - [OIDC_IDTOKEN_SUB_GENERATOR](#oidc_idtoken_sub_generator)
    - [OIDC_SKIP_CONSENT_ENABLE](#oidc_skip_consent_enable)
    - [OIDC_SKIP_CONSENT_EXPIRE](#oidc_skip_consent_expire)
    - [OIDC_TOKEN_EXPIRE](#oidc_token_expire)
    - [OIDC_USERINFO](#oidc_userinfo)

## Requirements

- Python: `2.7` `3.4`
- Django: `1.7` `1.8` `1.9`

## Installation

If you want to get started fast see our `/example_project` folder.

Install the package using pip.

```bash
$ pip install django-oidc-provider
```

Add it to your apps.

```python
INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'oidc_provider',
    # ...
)
```

Add the provider urls.

```python
urlpatterns = patterns('',
    # ...
    url(r'^openid/', include('oidc_provider.urls', namespace='oidc_provider')),
    # ...
)
```

Generate server RSA key and run migrations (if you don't).

```bash
python manage.py creatersakey
python manage.py migrate
```

Add required variables to your project settings.

```python
# You maybe have this on top of your settings.py
import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))


SITE_URL = 'http://localhost:8000'
LOGIN_URL = '/accounts/login/'
OIDC_RSA_KEY_FOLDER = BASE_DIR
```

## Users And Clients

User and client creation it's up to you. This is because is out of the scope in the core implementation of OIDC.
So, there are different ways to create your Clients. By displaying a HTML form or maybe if you have internal thrusted Clients you can create them programatically.

[Read more about client creation](http://tools.ietf.org/html/rfc6749#section-2).

For your users, the tipical situation is that you provide them a login and a registration page.

If you want to test the provider without getting to deep into this topics you can:

Create a user with: ``python manage.py createsuperuser``.

Create clients using Django admin (if you have it enabled):

![Client Creation](http://i64.tinypic.com/2dsfgoy.png)

Or create a client with Django shell: ``python manage.py shell``:

```python
>>> from oidc_provider.models import Client
>>> c = Client(name='Some Client', client_id='123', client_secret='456', response_type='code', redirect_uris=['http://example.com/'])
>>> c.save()
```

## Server RSA Keys

Server keys are used to sign/encrypt ID Tokens. These keys are stored in the `RSAKey` model. So the package will automatically generate public keys and expose them in the `jwks_uri` endpoint.

You can easily create them with the admin:

![RSAKey Creation](http://i64.tinypic.com/vj2ma.png)

Or use `python manage.py creatersakey` command.

```curl
GET /openid/jwks HTTP/1.1
Host: localhost:8000
```
```json
{  
  "keys":[  
    {  
      "use":"sig",
      "e":"AQAB",
      "kty":"RSA",
      "alg":"RS256",
      "n":"3Gm0pS7ij_SnY96wkbaki74MUYJrobXecO6xJhvmAEEhMHGpO0m4H2nbOWTf6Jc1FiiSvgvhObVk9xPOM6qMTQ5D5pfWZjNk99qDJXvAE4ImM8S0kCaBJGT6e8JbuDllCUq8aL71t67DhzbnoBsKCnVOE1GJffpMcDdBUYkAsx8",
      "kid":"a38ea7fbf944cc060eaf5acc1956b0e3"
    }
  ]
}
```

## Templates

Add your own templates files inside a folder named ``templates/oidc_provider/``.
You can copy the sample html here and edit them with your own styles.

**authorize.html**

```html
<h1>Request for Permission</h1>

<p>Client <strong>{{ client.name }}</strong> would like to access this information of you ...</p>

<form method="post" action="{% url 'oidc_provider:authorize' %}">
    
    {% csrf_token %}

    {{ hidden_inputs }}

    <ul>
    {% for scope in params.scope %}
        <li>{{ scope | capfirst }}</li>
    {% endfor %}
    </ul>

    <input name="allow" type="submit" value="Authorize" />

</form>
```

**error.html**

```html
<h3>{{ error }}</h3>
<p>{{ description }}</p>
```

## Standard Claims

This subset of OpenID Connect defines a set of standard Claims. They are returned in the UserInfo Response.

The package comes with a setting called `OIDC_USERINFO`, basically it refers to a class that MUST have a class-method named `get_by_user`, this will be called with a Django `User` instance and returns an object with all the claims of the user as attributes.

List of all the attributes grouped by scopes:

| profile            | email          | phone                 | address                |
| ------------------ | -------------- | --------------------- | ---------------------- |
| name               | email          | phone_number          | address_formatted      |
| given_name         | email_verified | phone_number_verified | address_street_address |
| family_name        |                |                       | address_locality       |
| middle_name        |                |                       | address_region         |
| nickname           |                |                       | address_postal_code    |
| preferred_username |                |                       | address_country        |
| profile            |                |                       |                        |
| picture            |                |                       |                        |
| website            |                |                       |                        |
| gender             |                |                       |                        |
| birthdate          |                |                       |                        |
| zoneinfo           |                |                       |                        |
| locale             |                |                       |                        |
| updated_at         |                |                       |                        |

Example using a django model:

```python
from django.conf import settings
from django.db import models


class UserInfo(models.Model):

    GENDER_CHOICES = [
        ('F', 'Female'),
        ('M', 'Male'),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, primary_key=True)
    
    given_name = models.CharField(max_length=255, blank=True, null=True)
    family_name = models.CharField(max_length=255, blank=True, null=True)
    gender = models.CharField(max_length=100, choices=GENDER_CHOICES, null=True)
    birthdate = models.DateField(null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    email_verified = models.NullBooleanField(default=False)

    phone_number = models.CharField(max_length=255, blank=True, null=True)
    phone_number_verified = models.NullBooleanField(default=False)

    address_locality = models.CharField(max_length=255, blank=True, null=True)
    address_country = models.CharField(max_length=255, blank=True, null=True)

    @classmethod
    def get_by_user(cls, user):
        return cls.objects.get(user=user)

```

## Server Endpoints

**/authorize endpoint**

Example of an OpenID Authentication Request using the ``Authorization Code`` flow.

```curl
GET /openid/authorize?client_id=123&redirect_uri=http%3A%2F%2Fexample.com%2F&response_type=code&scope=openid%20profile%20email&state=abcdefgh HTTP/1.1
Host: localhost:8000
Cache-Control: no-cache
Content-Type: application/x-www-form-urlencoded
```

After the user accepts and authorizes the client application, the server redirects to:

```curl
http://example.com/?code=5fb3b172913448acadce6b011af1e75e&state=abcdefgh
```

The ``code`` param will be use it to obtain access token.

**/token endpoint**

```curl
POST /openid/token/ HTTP/1.1
Host: localhost:8000
Cache-Control: no-cache
Content-Type: application/x-www-form-urlencoded
    client_id=123&client_secret=456&redirect_uri=http%253A%252F%252Fexample.com%252F&grant_type=authorization_code&code=5fb3b172913448acadce6b011af1e75e&state=abcdefgh
```

**/userinfo endpoint**

```curl
POST /openid/userinfo/ HTTP/1.1
Host: localhost:8000
Authorization: Bearer 2b5e4400bfcf47aa9f6abb1d7432fc60
```

## Running Tests

Use [tox](https://pypi.python.org/pypi/tox) for running tests in each of the environments, also to run coverage among:

```bash
$ tox
```

If you have a Django project properly configured with the package. Then just run tests as normal.

```bash
$ python manage.py test --settings oidc_provider.tests.app.settings oidc_provider
```

Also tests run on every commit to the project, we use [travis](https://travis-ci.org/juanifioren/django-oidc-provider/) for this.

## Relying Parties

This provider was tested (and fully works) with these OIDC Clients:
- [Drupal OpenID Connect](https://www.drupal.org/project/openid_connect)
- [Passport OpenID Connect](https://github.com/jaredhanson/passport-openidconnect) (for NodeJS)
- [OIDCAndroidLib](https://github.com/kalemontes/OIDCAndroidLib) (for Android)
- [Amazon IAM OpenID Connect Identity Provider](https://console.aws.amazon.com/iam/home) (for AWS)
- [Amazon Cognito](https://console.aws.amazon.com/cognito/home) (for AWS Identity pools)

## Settings

##### SITE_URL
REQUIRED. The OP server url.

`str`. For example `http://localhost:8000`.

##### LOGIN_URL
REQUIRED. Used to log the user in. [Read more in Django docs](https://docs.djangoproject.com/en/1.7/ref/settings/#login-url).

`str`. Default is `/accounts/login/`.

##### OIDC_AFTER_USERLOGIN_HOOK
OPTIONAL. A string with the location of your function. Provide a way to plug into the process after the user has logged in, typically to perform some business logic.

Default is:
```python
def default_hook_func(request, user, client):
    return None
```

Return `None` if you want to continue with the flow.

The typical situation will be checking some state of the user or maybe redirect him somewhere.
With request you have access to all OIDC parameters. Remember that if you redirect the user to another place then you need to take him back to the authorize endpoint (use `request.get_full_path()` as the value for a "next" parameter).

##### OIDC_CODE_EXPIRE
OPTIONAL.

`int`. Expressed in seconds. Default is `60*10`.

##### OIDC_EXTRA_SCOPE_CLAIMS
OPTIONAL. A string with the location of your class. Default is `oidc_provider.lib.claims.AbstractScopeClaims`.

Used to add extra scopes specific for your app. This class MUST inherit ``AbstractScopeClaims``.

OpenID Connect Clients will use scope values to specify what access privileges are being requested for Access Tokens.

[Here](http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) you have the standard scopes defined by the protocol.

Check out an example of how to implement it:

```python
from oidc_provider.lib.claims import AbstractScopeClaims

class MyAppScopeClaims(AbstractScopeClaims):

    def setup(self):
        # Here you can load models that will be used
        # in more than one scope for example.
        # print self.user
        # print self.scopes
        try:
            self.some_model = SomeModel.objects.get(user=self.user)
        except SomeModel.DoesNotExist:
            # Create an empty model object.
            self.some_model = SomeModel()

    def scope_books(self, user):

        # Here you can search books for this user.

        dic = {
            'books_readed': books_readed_count,
        }

        return dic
```

See how we create our own scopes using the convention:

``def scope_<SCOPE_NAME>(self, user):``

If a field is empty or ``None`` will be cleaned from the response.

##### OIDC_IDTOKEN_EXPIRE
OPTIONAL.

`int`. Expressed in seconds. Default is `60*10`.

##### OIDC_IDTOKEN_SUB_GENERATOR
OPTIONAL. A string with the location of your function. `sub` is a locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client.

The function receives a `user` object and returns a unique `string` for the given user.

Default is:
```python
def default_sub_generator(user):

    return str(user.id)
```

##### OIDC_RSA_KEY_FOLDER
REQUIRED. Path of the folder where `OIDC_RSA_KEY.pem` lives. Used to sign/encrypt `id_token`. The package will automatically generate a public key and expose it in the `jwks_uri` endpoint.

You can easily create it using `python manage.py creatersakey` command.

##### OIDC_SKIP_CONSENT_ENABLE
OPTIONAL. If enabled, the Server will save the user consent given to a specific client, so that user won't be prompted for the same authorization multiple times.

`bool`. Default is `True`.

##### OIDC_SKIP_CONSENT_EXPIRE
OPTIONAL. User consent expiration after been granted.

`int`. Expressed in days. Default is `30*3`.

##### OIDC_TOKEN_EXPIRE
OPTIONAL. Token object expiration after been created.

`int`. Expressed in seconds. Default is `60*60`.

##### OIDC_USERINFO
OPTIONAL. A string with the location of your class. Read [standard claims](#standard-claims) section.
