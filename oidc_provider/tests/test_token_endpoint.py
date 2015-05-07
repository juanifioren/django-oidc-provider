import json
from urllib import urlencode
import uuid

from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase

from oidc_provider.lib.utils.token import *
from oidc_provider.tests.utils import *
from oidc_provider.views import *


class TokenTestCase(TestCase):
    """
    To obtain an Access Token and an ID Token, the RP Client sends a
    Token Request to the Token Endpoint to obtain a Token Response
    when using the Authorization Code Flow.
    """

    def setUp(self):
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')
        self.state = uuid.uuid4().hex

    def _post_request(self, post_data):
        """
        Makes a request to the token endpoint by sending the
        `post_data` parameters using the 'application/x-www-form-urlencoded'
        format.
        """
        url = reverse('oidc_provider:token')

        request = self.factory.post(url,
            data=urlencode(post_data),
            content_type='application/x-www-form-urlencoded')

        response = TokenView.as_view()(request)

        return response

    def _create_code(self):
        """
        Generate a valid grant code.
        """
        code = create_code(
            user=self.user,
            client=self.client,
            scope=['openid', 'email'])
        code.save()

        return code

    def test_request_methods(self):
        """
        Client sends an HTTP POST request to the Token Endpoint. Other request
        methods MUST NOT be allowed.
        """
        url = reverse('oidc_provider:token')

        requests = [
            self.factory.get(url),
            self.factory.put(url),
            self.factory.delete(url),
        ]

        for request in requests:
            response = TokenView.as_view()(request)

            self.assertEqual(response.status_code == 405, True,
                msg=request.method+' request does not return a 405 status.')

        request = self.factory.post(url)

        response = TokenView.as_view()(request)

        self.assertEqual(response.status_code == 400, True,
                msg=request.method+' request does not return a 400 status.')

    def test_client_authentication(self):
        """
        The authorization server support including the
        client credentials in the request-body using the `client_id` and
        `client_secret`parameters.

        See: http://tools.ietf.org/html/rfc6749#section-2.3.1
        """
        code = self._create_code()

        # Test a valid request to the token endpoint.
        post_data = {
            'client_id': self.client.client_id,
            'client_secret': self.client.client_secret,
            'redirect_uri': self.client.default_redirect_uri,
            'grant_type': 'authorization_code',
            'code': code.code,
            'state': self.state,
        }
        response = self._post_request(post_data)
        response_dic = json.loads(response.content)

        self.assertEqual('access_token' in response_dic, True,
                msg='"access_token" key is missing in response.')
        self.assertEqual('error' in response_dic, False,
                msg='"error" key should not exists in response.')

        # Now, test with an invalid client_id.
        invalid_data = post_data.copy()
        invalid_data['client_id'] = self.client.client_id * 2 # Fake id.

        # Create another grant code.
        code = self._create_code()
        invalid_data['code'] = code.code

        response = self._post_request(invalid_data)
        response_dic = json.loads(response.content)

        self.assertEqual('error' in response_dic, True,
                msg='"error" key should exists in response.')
        self.assertEqual(response_dic.get('error') == 'invalid_client', True,
                msg='"error" key value should be "invalid_client".')
