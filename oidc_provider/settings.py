import importlib

from django.conf import settings


class DefaultSettings(object):

    @property
    def LOGIN_URL(self):
        """
        REQUIRED.
        """
        return None

    @property
    def SITE_URL(self):
        """
        REQUIRED.
        """
        return None

    @property
    def OIDC_AFTER_USERLOGIN_HOOK(self):
        """
        OPTIONAL.
        """
        def default_hook_func(request, user, client):
            return None

        return default_hook_func

    @property
    def OIDC_CODE_EXPIRE(self):
        """
        OPTIONAL.
        """
        return 60*10

    @property
    def OIDC_EXTRA_SCOPE_CLAIMS(self):
        """
        OPTIONAL.
        """
        return 'oidc_provider.lib.claims.AbstractScopeClaims'

    @property
    def OIDC_IDTOKEN_EXPIRE(self):
        """
        OPTIONAL.
        """
        return 60*10

    @property
    def OIDC_IDTOKEN_SUB_GENERATOR(self):
        """
        OPTIONAL.
        """
        def default_sub_generator(user):
            return user.id

        return default_sub_generator

    @property
    def OIDC_TOKEN_EXPIRE(self):
        """
        OPTIONAL.
        """
        return 60*60


default_settings = DefaultSettings()


def import_from_str(value):
    """
    Attempt to import a class from a string representation.
    """
    try:
        parts = value.split('.')
        module_path, class_name = '.'.join(parts[:-1]), parts[-1]
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except ImportError as e:
        msg = 'Could not import %s for settings. %s: %s.' % (value, e.__class__.__name__, e)
        raise ImportError(msg)


def get(name, import_str=False):
    """
    Helper function to use inside the package.
    """
    try:
        value = getattr(default_settings, name)
        value = getattr(settings, name)
    except AttributeError:
        if value == None:
            raise Exception('You must set ' + name + ' in your settings.')

    value = import_from_str(value) if import_str else value

    return value
