from secrets import token_urlsafe
from uuid import uuid4


def generate_client_id() -> str:
    """
    Generate the client_id following the uniqueness requirement.

    NOTE: This is not cryptographically secure.

    > a unique string representing the registration information provided by the client.
    > The client identifier is not a secret; it is exposed to the resource owner and MUST NOT be used
    > alone for client authentication.

    See https://datatracker.ietf.org/doc/html/rfc6749

    Key features:

    - Uniqueness: Each client is assigned a unique ID.
    """
    return str(uuid4())


def generate_client_secret() -> str:
    """
    Generate a unique client_secret. This is required to be
    cryptographically secure.

    See https://docs.python.org/3/library/secrets.html
    """
    return token_urlsafe(32)
