from django.utils.translation import ugettext as _
from oidc_provider.models import UserInfo


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
        for key, value in dic.iteritems():

            if not value:
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
            self.userinfo = UserInfo.objects.get(user=self.user)
        except UserInfo.DoesNotExist:
            # Create an empty model object.
            self.userinfo = UserInfo()

    def scope_profile(self, user):
        dic = {
            'name': self.userinfo.name,
            'given_name': self.userinfo.given_name,
            'family_name': self.userinfo.family_name,
            'middle_name': self.userinfo.middle_name,
            'nickname': self.userinfo.nickname,
            'preferred_username': self.userinfo.preferred_username,
            'profile': self.userinfo.profile,
            'picture': self.userinfo.picture,
            'website': self.userinfo.website,
            'gender': self.userinfo.gender,
            'birthdate': self.userinfo.birthdate,
            'zoneinfo': self.userinfo.zoneinfo,
            'locale': self.userinfo.locale,
            'updated_at': self.userinfo.updated_at,
        }

        return dic

    def scope_email(self, user):
        dic = {
            'email': self.user.email,
            'email_verified': self.userinfo.email_verified,
        }

        return dic

    def scope_phone(self, user):
        dic = {
            'phone_number': self.userinfo.phone_number,
            'phone_number_verified': self.userinfo.phone_number_verified,
        }

        return dic

    def scope_address(self, user):
        dic = {
            'address': {
                'formatted': self.userinfo.address_formatted,
                'street_address': self.userinfo.address_street_address,
                'locality': self.userinfo.address_locality,
                'region': self.userinfo.address_region,
                'postal_code': self.userinfo.address_postal_code,
                'country': self.userinfo.address_country,
            }
        }

        return dic
