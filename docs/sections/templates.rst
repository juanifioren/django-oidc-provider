.. _templates:

Templates
#########

Add your own templates files inside a folder named ``templates/oidc_provider/``.
You can copy the sample html files here and customize them with your own style.

**authorize.html**::

    <h1>Request for Permission</h1>

    <p>Client <strong>{{ client.name }}</strong> would like to access this information of you ...</p>

    <form method="post" action="{% url 'oidc_provider:authorize' %}">

        {% csrf_token %}

        {{ hidden_inputs }}

        <ul>
        {% for scope in scopes %}
            <li><strong>{{ scope.name }}</strong><br><i>{{ scope.description }}</i></li>
        {% endfor %}
        </ul>

        <input type="submit" value="Decline" />
        <input name="allow" type="submit" value="Authorize" />

    </form>

**error.html**::

    <h3>{{ error }}</h3>
    <p>{{ description }}</p>

You can also customize paths to your custom templates by putting them in ``OIDC_TEMPLATES`` in the settings.

The following contexts will be passed to the ``authorize`` and ``error`` templates respectively::

    # For authorize template
    {
        'client': 'an instance of Client for the auth request',
        'hidden_inputs': 'a rendered html with all the hidden inputs needed for AuthorizeEndpoint',
        'params': 'a dict containing the params in the auth request',
        'scopes': 'a list of scopes'
    }

    # For error template
    {
        'error': 'string stating the error',
        'description': 'string stating description of the error'
    }
