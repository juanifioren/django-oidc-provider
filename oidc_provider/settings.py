import importlib

from django.conf import settings


class DefaultSettings(object):

    @property
    def LOGIN_URL(self):
        """
        REQUIRED. Used to log the user in.
        """
        return None

    @property
    def SITE_URL(self):
        """
        REQUIRED. The OP server url.
        """
        return None

    @property
    def OIDC_AFTER_USERLOGIN_HOOK(self):
        """
        OPTIONAL.  Provide a way to plug into the process after
        the user has logged in, typically to perform some business logic.
        """
        def default_hook_func(request, user, client):
            return None

        return default_hook_func

    @property
    def OIDC_CODE_EXPIRE(self):
        """
        OPTIONAL. Code expiration time expressed in seconds.
        """
        return 60*10

    @property
    def OIDC_EXTRA_SCOPE_CLAIMS(self):
        """
        OPTIONAL. A string with the location of your class.
        Used to add extra scopes specific for your app. 
        """
        return 'oidc_provider.lib.claims.AbstractScopeClaims'

    @property
    def OIDC_IDTOKEN_EXPIRE(self):
        """
        OPTIONAL. Id token expiration time expressed in seconds.
        """
        return 60*10

    @property
    def OIDC_IDTOKEN_SUB_GENERATOR(self):
        """
        OPTIONAL. Subject Identifier. A locally unique and never
        reassigned identifier within the Issuer for the End-User,
        which is intended to be consumed by the Client.
        """
        def default_sub_generator(user):
            return str(user.id)

        return default_sub_generator

    @property
    def OIDC_RSA_KEY_FOLDER(self):
        """
        REQUIRED.
        """
        return None

    @property
    def OIDC_SKIP_CONSENT_ENABLE(self):
        """
        OPTIONAL. If enabled, the Server will save the user consent
        given to a specific client, so that user won't be prompted for
        the same authorization multiple times.
        """
        return True

    @property
    def OIDC_SKIP_CONSENT_EXPIRE(self):
        """
        OPTIONAL. User consent expiration after been granted.
        """
        return 30*3

    @property
    def OIDC_TOKEN_EXPIRE(self):
        """
        OPTIONAL. Token object expiration after been created.
        Expressed in seconds.
        """
        return 60*60

    @property
    def OIDC_USERINFO(self):
        """
        OPTIONAL. A string with the location of your class.
        Used to add extra scopes specific for your app. 
        """
        return 'oidc_provider.lib.utils.common.DefaultUserInfo'

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
