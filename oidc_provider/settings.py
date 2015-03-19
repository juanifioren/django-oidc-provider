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
        from oidc_provider.lib.claims import AbstractScopeClaims

        return AbstractScopeClaims

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

def get(name):
    '''
    Helper function to use inside the package.
    '''
    try:
        value = getattr(default_settings, name)
        value = getattr(settings, name)
    except AttributeError:
        if value == None:
            raise Exception('You must set ' + name + ' in your settings.')

    return value