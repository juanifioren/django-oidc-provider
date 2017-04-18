.. _templates:

Templates
#########

Add your own templates files inside a folder named ``templates/oidc_provider/``.
You can copy the sample html here and edit them with your own styles.

**authorize.html**::

    <h1>Request for Permission</h1>

    <p>Client <strong>{{ client.name }}</strong> would like to access this information of you ...</p>

    <form method="post" action="{% url 'oidc_provider:authorize' %}">

        {% csrf_token %}

        {{ hidden_inputs }}

        <ul>
        {% for scope in params.scope %}
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

