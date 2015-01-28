from django.utils.translation import ugettext as _

from openid_provider.models import UserInfo


# Standard Claims
# http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

class StandardClaims(object):

    __model__ = UserInfo

    def __init__(self, user, scopes):
        self.user = user
        self.scopes = scopes

        try:
            self.model = self.__model__.objects.get(user=self.user)
        except self.__model__.DoesNotExist:
            self.model = self.__model__()

    def create_response_dic(self):

        dic = {}

        for scope in self.scopes:

            if scope in self._scopes_registered():
                dic.update(getattr(self, 'scope_' + scope))

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
                aux_dic[key] = clean_dic(value)

        return aux_dic

    @property
    def scope_profile(self):
        dic = {
            'name': self.model.name,
            'given_name': self.model.given_name,
            'family_name': self.model.family_name,
            'middle_name': self.model.middle_name,
            'nickname': self.model.nickname,
            'preferred_username': self.model.preferred_username,
            'profile': self.model.profile,
            'picture': self.model.picture,
            'website': self.model.website,
            'gender': self.model.gender,
            'birthdate': self.model.birthdate,
            'zoneinfo': self.model.zoneinfo,
            'locale': self.model.locale,
            'updated_at': self.model.updated_at,
        }

        return dic

    @property
    def scope_email(self):
        dic = {
            'email': self.user.email,
            'email_verified': self.model.email_verified,
        }

        return dic

    @property
    def scope_phone(self):
        dic = {
            'phone_number': self.model.phone_number,
            'phone_number_verified': self.model.phone_number_verified,
        }

        return dic

    @property
    def scope_address(self):
        dic = {
            'address': {
                'formatted': self.model.address_formatted,
                'street_address': self.model.address_street_address,
                'locality': self.model.address_locality,
                'region': self.model.address_region,
                'postal_code': self.model.address_postal_code,
                'country': self.model.address_country,
            }
        }

        return dic
