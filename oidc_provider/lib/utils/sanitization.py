import re


def sanitize_client_id(client_id):
    """
    Sanitize client_id according to OAuth 2.0 RFC 6749 specification.

    Removes control characters that can cause database errors while preserving
    all valid visible ASCII characters (VCHAR: 0x21-0x7E) as defined by the
    OAuth 2.0 specification.

    Args:
        client_id (str): The client_id parameter from the request

    Returns:
        str: Sanitized client_id with control characters removed

    Examples:
        >>> sanitize_client_id("Hello\\x00World")
        'HelloWorld'
        >>> sanitize_client_id("valid-client-123")
        'valid-client-123'
        >>> sanitize_client_id("")
        ''
        >>> sanitize_client_id(None)
        ''
    """
    if not client_id:
        return ""

    return re.sub(r"[^\x21-\x7E]", "", client_id)
