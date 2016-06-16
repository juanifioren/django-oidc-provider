from django.utils.translation import ugettext as _

from oidc_provider import settings


class ScopeClaims(object):

    def __init__(self, user, scopes):
        self.user = user
        self.userinfo = settings.get('OIDC_USERINFO', import_str=True).get_by_user(self.user)
        self.scopes = scopes

    def create_response_dic(self):
        """
        Generate the dic that will be jsonify. Checking scopes given vs
        registered.

        Returns a dic.
        """
        dic = {}

        for scope in self.scopes:
            if scope in self._scopes_registered():
                dic.update(getattr(self, 'scope_' + scope)())

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

    @classmethod
    def get_scopes_info(cls, scopes=[]):
        scopes_info = []

        for name in cls.__dict__:
            if name.startswith('info_'):
                scope_name = name.split('info_')[1]
                if scope_name in scopes:
                    touple_info = getattr(cls, name)
                    scopes_info.append({
                        'scope': scope_name,
                        'name': touple_info[0],
                        'description': touple_info[1],
                    })

        return scopes_info


class StandardScopeClaims(ScopeClaims):
    """
    Based on OpenID Standard Claims.
    See: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    """

    info_profile = (
        _(u'Basic profile'),
        _(u'Access to your basic information. Includes names, gender, birthdate and other information.'),
    )
    def scope_profile(self):
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

    info_email = (
        _(u'Email'),
        _(u'Access to your email address.'),
    )
    def scope_email(self):
        dic = {
            'email': getattr(self.user, 'email', None),
            'email_verified': getattr(self.userinfo, 'email_verified', None),
        }

        return dic

    info_phone = (
        _(u'Phone number'),
        _(u'Access to your phone number.'),
    )
    def scope_phone(self):
        dic = {
            'phone_number': getattr(self.userinfo, 'phone_number', None),
            'phone_number_verified': getattr(self.userinfo, 'phone_number_verified', None),
        }

        return dic

    info_address = (
        _(u'Address information'),
        _(u'Access to your address. Includes country, locality, street and other information.'),
    )
    def scope_address(self):
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
