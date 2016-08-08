try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode
import uuid

from django.contrib.auth.models import AnonymousUser
from django.core.management import call_command
from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.test import TestCase

from oidc_provider.models import *
from oidc_provider.tests.app.utils import *
from oidc_provider.views import *


class CodeFlowTestCase(TestCase):
    """
    Test cases for Authorization Code Flow.
    """

    def setUp(self):
        call_command('creatersakey')
        self.factory = RequestFactory()
        self.user = create_fake_user()
        self.client = create_fake_client(response_type='code')
        self.client_public = create_fake_client(response_type='code', is_public=True)
        self.state = uuid.uuid4().hex
        self.nonce = uuid.uuid4().hex

    def _auth_request(self, method, data={}, is_user_authenticated=False):
        url = reverse('oidc_provider:authorize')

        if method.lower() == 'get':
            query_str = urlencode(data).replace('+', '%20')
            if query_str:
                url += '?' + query_str
            request = self.factory.get(url)
        elif method.lower() == 'post':
            request = self.factory.post(url, data=data)
        else:
            raise Exception('Method unsupported for an Authorization Request.')

        # Simulate that the user is logged.
        request.user = self.user if is_user_authenticated else AnonymousUser()

        response = AuthorizeView.as_view()(request)

        return response
