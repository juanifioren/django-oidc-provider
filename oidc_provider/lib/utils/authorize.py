try:
    from urllib import urlencode

    from urlparse import parse_qs
    from urlparse import urlsplit
    from urlparse import urlunsplit
except ImportError:
    from urllib.parse import parse_qs
    from urllib.parse import urlencode
    from urllib.parse import urlsplit
    from urllib.parse import urlunsplit


def strip_prompt_login(path):
    """
    Strips 'login' from the 'prompt' query parameter.
    """
    uri = urlsplit(path)
    query_params = parse_qs(uri.query)
    prompt_list = query_params.get("prompt", "")[0].split()
    if "login" in prompt_list:
        prompt_list.remove("login")
        query_params["prompt"] = " ".join(prompt_list)
    if not query_params["prompt"]:
        del query_params["prompt"]
    uri = uri._replace(query=urlencode(query_params, doseq=True))
    return urlunsplit(uri)
