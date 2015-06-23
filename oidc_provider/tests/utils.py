from django.contrib.auth.models import User
from oidc_provider.models import *


def create_fake_user():
    """
    Create a test user.

    Return a User object.
    """
    user = User()
    user.username = 'johndoe'
    user.email = 'johndoe@example.com'
    user.set_password('1234')

    user.save()

    return user

def create_fake_client(response_type):
    """
    Create a test client, response_type argument MUST be:
    'code', 'id_token' or 'id_token token'.

    Return a Client object.
    """
    client = Client()
    client.name = 'Some Client'
    client.client_id = '123'
    client.client_secret = '456'
    client.response_type = response_type
    client.redirect_uris = ['http://example.com/']

    client.save()

    return client

def is_code_valid(url, user, client):
    """
    Check if the code inside the url is valid.
    """
    try:
        code = (url.split('code='))[1].split('&')[0]
        code = Code.objects.get(code=code)
        is_code_ok = (code.client == client) and \
                     (code.user == user)
    except:
        is_code_ok = False

    return is_code_ok
