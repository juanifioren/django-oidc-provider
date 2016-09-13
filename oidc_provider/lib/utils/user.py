from oidc_provider.models import Token


def get_authorized_clients(user):
    """
    Utilitary function that evaluates and returns the authorized clients for
    a user.
    """
    return set(map(lambda t: t.client, Token.objects.filter(user=user)))
