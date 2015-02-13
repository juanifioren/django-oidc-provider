
Django-OIDC-Provider
####################

**This project is in ALFA version and is rapidly changing. DO NOT USE IT FOR PRODUCTION SITES.**

Important things that you should know:

- Although OpenID was built on top of OAuth2, this isn't an OAuth2 server. Maybe in a future it will be.
- Despite that implementation MUST support TLS. You can make request without using SSL. There is no control on that.
- This cover ``authorization_code`` flow and ``implicit`` flow, NO support for ``hybrid`` flow at this moment.
- Only support for requesting Claims using Scope Values.

************
Installation
************

Install the package using pip.

.. code:: bash
    
    pip install git+https://github.com/juanifioren/django-oidc-provider.git#egg=openid_provider


Add it to your apps.

.. code:: python

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

Add the provider urls.

.. code:: python

    urlpatterns = patterns('',
        # ...
        url(r'^openid/', include('openid_provider.urls', namespace='openid_provider')),
        # ...
    )

********
Settings
********

Add required variables to your project settings.

.. code:: python

    # REQUIRED.

    # Your server provider url.
    SITE_URL = 'http://localhost:8000'

    # Used to log the user in.
    # See: https://docs.djangoproject.com/en/1.7/ref/settings/#login-url
    LOGIN_URL = '/accounts/login/'

    # OPTIONAL.

    DOP_CODE_EXPIRE = 60*10 # 10 min.
    DOP_EXTRA_SCOPE_CLAIMS = MyAppScopeClaims,
    DOP_IDTOKEN_EXPIRE = 60*10, # 10 min.
    DOP_TOKEN_EXPIRE = 60*60 # 1 hour.


********************
Create User & Client
********************

First of all, we need to create a user: ``python manage.py createsuperuser``.

Then let's create a Client. Start django shell: ``python manage.py shell``.

.. code:: python

    >>> from openid_provider.models import Client
    >>> c = Client(name='Some Client', client_id='123', client_secret='456', response_type='code', redirect_uris=['http://example.com/'])
    >>> c.save()

****************
Server Endpoints
****************

**/authorize endpoint**

Example of an OpenID Authentication Request using the ``Authorization Code`` flow.

.. code:: curl

    GET /openid/authorize?client_id=123&redirect_uri=http%3A%2F%2Fexample.com%2F&response_type=code&scope=openid%20profile%20email&state=abcdefgh HTTP/1.1
    Host: localhost:8000
    Cache-Control: no-cache
    Content-Type: application/x-www-form-urlencoded

After the user accepts and authorizes the client application, the server redirects to:

.. code:: curl

    http://example.com/?code=5fb3b172913448acadce6b011af1e75e&state=abcdefgh

The ``code`` param will be use it to obtain access token.

**/token endpoint**

.. code:: curl

    POST /openid/token/ HTTP/1.1
    Host: localhost:8000
    Cache-Control: no-cache
    Content-Type: application/x-www-form-urlencoded

    client_id=123&client_secret=456&redirect_uri=http%253A%252F%252Fexample.com%252F&grant_type=authorization_code&code=[CODE]&state=abcdefgh

**/userinfo endpoint**

.. code:: curl

    POST /openid/userinfo/ HTTP/1.1
    Host: localhost:8000
    Authorization: Bearer [ACCESS_TOKEN]

***************
Claims & Scopes
***************

OpenID Connect Clients will use scope values to specify what access privileges are being requested for Access Tokens.

Here you have the standard scopes defined by the protocol.
http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims

If you need to add extra scopes specific for your app you can add them using the ``DOP_EXTRA_SCOPE_CLAIMS`` settings variable.
This class MUST inherit ``AbstractScopeClaims``.

Check out an example:

.. code:: python
    
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

See how we create our own scopes using the convention ``def scope_<SCOPE_NAME>(self, user):``.
If a field is empty or ``None`` will be cleaned from the response.

**Don't forget to add your class into your app settings.**

*********
Templates
*********

Add your own templates files inside a folder named ``templates/openid_provider/``.
You can copy the sample html here and edit them with your own styles.

**authorize.html**

.. code:: html
    
    <h1>Request for Permission</h1>

    <p>Client <strong>{{ client.name }}</strong> would like to access this information of you ...</p>

    <form method="post" action="{% url 'openid_provider:authorize' %}">
        
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

**error.html**

.. code:: html
    
    <h3>{{ error }}</h3>
    <p>{{ description }}</p>

*************
Running tests
*************

Just run them as normal Django tests.

.. code:: bash
    
    $ python manage.py test openid_provider

************
Contributing
************

We love contributions, so please feel free to fix bugs, improve things, provide documentation. Just submit a Pull Request.
