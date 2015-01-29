from django.conf import settings


# Here goes all the package default settings.
default_settings = {
    'DOP_CODE_EXPIRE': 60 * 10,  # 10 min.
    'DOP_IDTOKEN_EXPIRE': 60 * 10,  # 10 min.
    'DOP_TOKEN_EXPIRE': 60 * 60,  # 1 hour.
    'LOGIN_URL': None,
    'SITE_URL': None,
}


def get(name):
    """
    Helper function to use inside the package.
    :param name:
    :return:
    """
    try:
        value = default_settings[name]
        value = getattr(settings, name)
    except AttributeError:
        if value == None:
            raise Exception('You must set ' + name + ' in your settings.')

    return value
