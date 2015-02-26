# Welcome to the Docs!

Django OIDC Provider can help you providing out of the box all the endpoints, data and logic needed to add OpenID Connect capabilities to your Django projects.

**This project is still in DEVELOPMENT and is rapidly changing. DO NOT USE IT FOR PRODUCTION SITES, unless you know what you do.**

Before getting started there are some important things that you should know:
* Although OpenID was built on top of OAuth2, this isn't an OAuth2 server. Maybe in a future it will be.
* Despite that implementation MUST support TLS. You can make request without using SSL. There is no control on that.
* This cover authorization_code flow and implicit flow, NO support for hybrid flow at this moment.
* Only support for requesting Claims using Scope Values.

# Table Of Contents

- [Installation](#installation)
- [Settings](#settings)
- [Users And Clients](#users-and-clients)
- [Templates](#templates)
- [Server Endpoints](#server-endpoints)
- [Claims And Scopes](#claims-and-scopes)

## Installation

Install the package using pip.

```bash
pip install django-oidc-provider
# Or latest code from repo.
pip install git+https://github.com/juanifioren/django-oidc-provider.git#egg=openid_provider
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
    'openid_provider',
    # ...
)
```

Add the provider urls.

```python
urlpatterns = patterns('',
    # ...
    url(r'^openid/', include('openid_provider.urls', namespace='openid_provider')),
    # ...
)
```

## Settings

Add required variables to your project settings.

```python
# REQUIRED SETTINGS.

# Your server provider url.
SITE_URL = 'http://localhost:8000'

# Used to log the user in.
# See: https://docs.djangoproject.com/en/1.7/ref/settings/#login-url
LOGIN_URL = '/accounts/login/'

# OPTIONAL SETTINGS.

DOP_CODE_EXPIRE = 60*10 # 10 min.
DOP_EXTRA_SCOPE_CLAIMS = MyAppScopeClaims,
DOP_IDTOKEN_EXPIRE = 60*10, # 10 min.
DOP_TOKEN_EXPIRE = 60*60 # 1 hour.
```

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

{% endblock %}
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

## Claims And Scopes

OpenID Connect Clients will use scope values to specify what access privileges are being requested for Access Tokens.

Here you have the standard scopes defined by the protocol.
http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims

If you need to add extra scopes specific for your app you can add them using the ``DOP_EXTRA_SCOPE_CLAIMS`` settings variable.
This class MUST inherit ``AbstractScopeClaims``.

Check out an example:

```python
from openid_provider.lib.claims import AbstractScopeClaims

class MyAppScopeClaims(AbstractScopeClaims):

    def __init__(self, user, scopes):
        # Don't forget this.
        super(StandardScopeClaims, self).__init__(user, scopes)

        # Here you can load models that will be used
        # in more than one scope for example.
        try:
            self.some_model = SomeModel.objects.get(user=self.user)
        except UserInfo.DoesNotExist:
            # Create an empty model object.
            self.some_model = SomeModel()

    def scope_books(self, user):

        # Here you can search books for this user.
        # Remember that you have "self.some_model" also.

        dic = {
            'books_readed': books_readed_count,
        }

        return dic
```

See how we create our own scopes using the convention:

``def scope_<SCOPE_NAME>(self, user):``

If a field is empty or ``None`` will be cleaned from the response.

**Don't forget to add your class into your app settings.**