from django.utils.translation import ugettext as _

from oidc_provider import settings


class AbstractScopeClaims(object):

    def __init__(self, user, scopes):
        self.user = user
        self.scopes = scopes

        self.setup()

    def setup(self):
        pass

    def create_response_dic(self):
        """
        Generate the dic that will be jsonify. Checking scopes given vs
        registered.

        Returns a dic.
        """
        dic = {}

        for scope in self.scopes:
            if scope in self._scopes_registered():
                dic.update(getattr(self, 'scope_' + scope)(self.user))

        dic = self._clean_dic(dic)

        return dic

    def _scopes_registered(self):
        """
        Return a list that contains all the scopes registered
        in the class.
        """
        scopes = []

        for name in self.__class__.__dict__:

            if name.startswith('scope_'):
                scope = name.split('scope_')[1]
                scopes.append(scope)

        return scopes

    def _clean_dic(self, dic):
        """
        Clean recursively all empty or None values inside a dict.
        """
        aux_dic = dic.copy()
        for key, value in iter(dic.items()):

            if value is None or value == '':
                del aux_dic[key]
            elif type(value) is dict:
                aux_dic[key] = self._clean_dic(value)

        return aux_dic


class StandardScopeClaims(AbstractScopeClaims):
    """
    Based on OpenID Standard Claims.
    See: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    """

    def setup(self):
        try:
            self.userinfo = settings.get('OIDC_USERINFO',
                                         import_str=True).get_by_user(self.user)
        except:
            self.userinfo = None

    def scope_profile(self, user):
        dic = {
            'name': getattr(self.userinfo, 'name', None),
            'given_name': getattr(self.userinfo, 'given_name', None),
            'family_name': getattr(self.userinfo, 'family_name', None),
            'middle_name': getattr(self.userinfo, 'middle_name', None),
            'nickname': getattr(self.userinfo, 'nickname', None),
            'preferred_username': getattr(self.userinfo, 'preferred_username', None),
            'profile': getattr(self.userinfo, 'profile', None),
            'picture': getattr(self.userinfo, 'picture', None),
            'website': getattr(self.userinfo, 'website', None),
            'gender': getattr(self.userinfo, 'gender', None),
            'birthdate': getattr(self.userinfo, 'birthdate', None),
            'zoneinfo': getattr(self.userinfo, 'zoneinfo', None),
            'locale': getattr(self.userinfo, 'locale', None),
            'updated_at': getattr(self.userinfo, 'updated_at', None),
        }

        return dic

    def scope_email(self, user):
        dic = {
            'email': getattr(self.user, 'email', None),
            'email_verified': getattr(self.userinfo, 'email_verified', None),
        }

        return dic

    def scope_phone(self, user):
        dic = {
            'phone_number': getattr(self.userinfo, 'phone_number', None),
            'phone_number_verified': getattr(self.userinfo, 'phone_number_verified', None),
        }

        return dic

    def scope_address(self, user):
        dic = {
            'address': {
                'formatted': getattr(self.userinfo, 'address_formatted', None),
                'street_address': getattr(self.userinfo, 'address_street_address', None),
                'locality': getattr(self.userinfo, 'address_locality', None),
                'region': getattr(self.userinfo, 'address_region', None),
                'postal_code': getattr(self.userinfo, 'address_postal_code', None),
                'country': getattr(self.userinfo, 'address_country', None),
            }
        }

        return dic
