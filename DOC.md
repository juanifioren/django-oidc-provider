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
- [Users And Clients](#users-and-clients)
- [Templates](#templates)
- [Server Endpoints](#server-endpoints)
- [Running Tests](#running-tests)

## Requirements

- Python: `2.7.*`
- Django: `1.7.*` `1.8.*`

## Installation

If you want to get started fast see our [Example Project](https://github.com/juanifioren/django-oidc-provider/tree/master/example_project) folder.

Install the package using pip.

```bash
pip install django-oidc-provider
# Or latest code from repo.
pip install git+https://github.com/juanifioren/django-oidc-provider.git#egg=oidc_provider
# Or if working from a local repo
pip install git+./#egg=oidc_provider
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

## Settings

Add required variables to your project settings.

##### SITE_URL
REQUIRED. The OP server url.

`str`. For example `http://localhost:8000`.

##### LOGIN_URL
REQUIRED. Used to log the user in. [Read more in Django docs](https://docs.djangoproject.com/en/1.7/ref/settings/#login-url).

`str`. Default is `/accounts/login/`.

##### OIDC_AFTER_USERLOGIN_HOOK
OPTIONAL. Provide a way to plug into the process after the user has logged in, typically to perform some business logic.

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

`bool`. Expressed in seconds. Default is `60*10`.

##### OIDC_IDTOKEN_SUB_GENERATOR
OPTIONAL. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client.

Is just a function that receives a `user` object. Returns a unique string for the given user.

Default is:
```python
def default_sub_generator(user):

    return user.id
```

##### OIDC_TOKEN_EXPIRE
OPTIONAL. Token object expiration after been created.

`int`. Expressed in seconds. Default is `60*60`.

##### OIDC_USER_CONSENT_ENABLE
OPTIONAL. If enabled, the Server will save the user consent given to a specific client, so that user won't be prompted for the same authorization multiple times.

`bool`. Default is `True`.

##### OIDC_USER_CONSENT_EXPIRE
OPTIONAL. User consent expiration after been granted.

`int`. Expressed in days. Default is `30*3`.

## Users And Clients

User and client creation it's up to you. This is because is out of the scope in the core implementation of OIDC.
So, there are different ways to create your Clients. By displaying a HTML form or maybe if you have internal thrusted Clients you can create them programatically.

[Read more about client creation](http://tools.ietf.org/html/rfc6749#section-2).

For your users, the tipical situation is that you provide them a login and a registration page.

If you want to test the provider without getting to deep into this topics you can:

Create a user with: ``python manage.py createsuperuser``.

And then create a Client with django shell: ``python manage.py shell``.

```python
>>> from oidc_provider.models import Client
>>> c = Client(name='Some Client', client_id='123', client_secret='456', response_type='code', redirect_uris=['http://example.com/'])
>>> c.save()
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
    client_id=123&client_secret=456&redirect_uri=http%253A%252F%252Fexample.com%252F&grant_type=authorization_code&code=[CODE]&state=abcdefgh
```

**/userinfo endpoint**

```curl
POST /openid/userinfo/ HTTP/1.1
Host: localhost:8000
Authorization: Bearer [ACCESS_TOKEN]
```

## Running Tests

You need a Django project properly configured with the package. Then just run tests as normal.

```bash
$ python manage.py test oidc_provider
```

This provider was tested (and fully works) with these OIDC Clients:
- [Drupal OpenID Connect](https://www.drupal.org/project/openid_connect)
- [Passport OpenID Connect](https://github.com/jaredhanson/passport-openidconnect) (for NodeJS)
