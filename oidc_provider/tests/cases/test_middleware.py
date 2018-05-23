try:
    from django.urls import url
except ImportError:
    from django.conf.urls import url
from django.test import TestCase, override_settings
from django.views.generic import View
from mock import mock


class StubbedViews:
    class SampleView(View):
        pass

    urlpatterns = [url('^test/', SampleView.as_view())]


MW_CLASSES = ('django.contrib.sessions.middleware.SessionMiddleware',
              'oidc_provider.middleware.SessionManagementMiddleware')


@override_settings(ROOT_URLCONF=StubbedViews,
                   MIDDLEWARE=MW_CLASSES,
                   MIDDLEWARE_CLASSES=MW_CLASSES,
                   OIDC_SESSION_MANAGEMENT_ENABLE=True)
class MiddlewareTestCase(TestCase):

    def setUp(self):
        patcher = mock.patch('oidc_provider.middleware.get_browser_state_or_default')
        self.mock_get_state = patcher.start()

    def test_session_management_middleware_sets_cookie_on_response(self):
        response = self.client.get('/test/')

        self.assertIn('op_browser_state', response.cookies)
        self.assertEqual(response.cookies['op_browser_state'].value,
                         str(self.mock_get_state.return_value))
        self.mock_get_state.assert_called_once_with(response.wsgi_request)

    @override_settings(OIDC_SESSION_MANAGEMENT_ENABLE=False)
    def test_session_management_middleware_does_not_set_cookie_if_session_management_disabled(self):
        response = self.client.get('/test/')

        self.assertNotIn('op_browser_state', response.cookies)
