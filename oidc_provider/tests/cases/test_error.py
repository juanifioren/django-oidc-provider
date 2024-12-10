from django.test import TestCase
from oidc_provider.lib.errors import AuthorizeError

try:
    from urllib.parse import (
        urlparse,
        parse_qsl
    )
except ImportError:
    from urlparse import (
        urlparse,
        parse_qsl
    )


def compare(expected, created):
    """Compare expected and created urls"""
    ex_parsed = list(urlparse(expected))
    ex_qp = dict(parse_qsl(ex_parsed[4]))
    ex_frag = dict(parse_qsl(ex_parsed[5]))

    cr_parsed = list(urlparse(created))
    cr_qp = dict(parse_qsl(cr_parsed[4]))
    cr_frag = dict(parse_qsl(cr_parsed[5]))

    # Validate scheme, netloc, path match
    assert ex_parsed[:3] == cr_parsed[:3]
    # Validate qp and frags match
    assert ex_qp == cr_qp
    assert ex_frag == cr_frag


class TestImplicitAuthorizeErrorNonImplicit(TestCase):
    """Tests with grant_type code - all responses in query params"""
    redirect_uri = 'https://example.com/'
    grant_type = 'code'
    error = 'login_required'
    desc = 'The+Authorization+Server+requires+End-User+authentication'

    def test_no_params(self):
        """Test with a path only and no query/frag params"""
        redirect_uri = self.redirect_uri + 'path'
        error = AuthorizeError(redirect_uri, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri, '')
        expected_uri = '{}?error={}&error_description={}'.format(
            redirect_uri, self.error, self.desc)
        compare(expected_uri, created_uri)

    def test_query_params_only(self):
        """Test with query param in redirect uri"""
        redirect_uri = self.redirect_uri + "path/?action=something"
        error = AuthorizeError(redirect_uri, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri, '')
        expected_uri = '{}&error={}&error_description={}'.format(
            redirect_uri, self.error, self.desc)
        compare(expected_uri, created_uri)

    def test_frag_params_only(self):
        """Test with fragment params only"""
        redirect_uri = self.redirect_uri + 'path'
        frag = '#action=something'
        error = AuthorizeError(redirect_uri + frag, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri + frag, '')
        expected_uri = '{}path?error={}&error_description={}{}'.format(
            self.redirect_uri, self.error, self.desc, frag)
        compare(expected_uri, created_uri)

    def test_query_and_frag_params(self):
        """Test with both qp's and fragment"""
        redirect_uri = self.redirect_uri + 'path?my_qp=test'
        frag = '#action=something'
        error = AuthorizeError(redirect_uri + frag, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri + frag, '')
        expected_uri = '{}path?my_qp=test&error={}&error_description={}{}' \
            .format(self.redirect_uri, self.error, self.desc, frag)
        compare(expected_uri, created_uri)

    def test_with_state(self):
        """Test with state"""
        redirect_uri = self.redirect_uri + 'path'
        state = 'my_state'
        error = AuthorizeError(redirect_uri, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri, state)
        expected_uri = '{}path?error={}&error_description={}&state={}' \
            .format(self.redirect_uri, self.error, self.desc, state)
        compare(expected_uri, created_uri)

    def test_with_deep_link(self):
        """Test with a non-http schema; deep link style (think slack://)"""
        redirect_uri = 'slack://example.com/path'
        state = 'my_state'
        error = AuthorizeError(redirect_uri, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri, state)
        expected_uri = '{}?error={}&error_description={}&state={}' \
            .format(redirect_uri, self.error, self.desc, state)
        compare(expected_uri, created_uri)


class TestImplicitAuthorizeErrorImplicit(TestCase):
    """Tests with grant_type code - all responses in query params"""
    redirect_uri = 'https://example.com/'
    grant_type = 'implicit'
    error = 'login_required'
    desc = 'The+Authorization+Server+requires+End-User+authentication'

    def test_no_params(self):
        """Test with a path only and no query/frag params"""
        redirect_uri = self.redirect_uri + 'path'
        error = AuthorizeError(redirect_uri, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri, '')
        expected_uri = '{}#error={}&error_description={}'.format(
            redirect_uri, self.error, self.desc)
        compare(expected_uri, created_uri)

    def test_query_params_only(self):
        """Test with query param in redirect uri"""
        redirect_uri = self.redirect_uri + "path/?action=something"
        error = AuthorizeError(redirect_uri, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri, '')
        expected_uri = '{}#error={}&error_description={}'.format(
            redirect_uri, self.error, self.desc)
        compare(expected_uri, created_uri)

    def test_frag_params_only(self):
        """Test with fragment params only"""
        redirect_uri = self.redirect_uri + 'path'
        frag = '#action=something'
        error = AuthorizeError(redirect_uri + frag, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri + frag, '')
        expected_uri = '{}path{}&error={}&error_description={}'.format(
            self.redirect_uri, frag, self.error, self.desc)
        compare(expected_uri, created_uri)

    def test_query_and_frag_params(self):
        """Test with both qp's and fragment"""
        redirect_uri = self.redirect_uri + 'path?my_qp=test'
        frag = '#action=something'
        error = AuthorizeError(redirect_uri + frag, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri + frag, '')
        expected_uri = '{}path?my_qp=test{}&error={}&error_description={}' \
            .format(self.redirect_uri, frag, self.error, self.desc)
        compare(expected_uri, created_uri)

    def test_with_state(self):
        """Test with state"""
        redirect_uri = self.redirect_uri + 'path'
        state = 'my_state'
        error = AuthorizeError(redirect_uri, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri, state)
        expected_uri = '{}path#error={}&error_description={}&state={}' \
            .format(self.redirect_uri, self.error, self.desc, state)
        compare(expected_uri, created_uri)

    def test_with_deep_link(self):
        """Test with a non-http schema; deep link style (think slack://)"""
        redirect_uri = 'slack://example.com/path'
        state = 'my_state'
        error = AuthorizeError(redirect_uri, self.error, self.grant_type)
        created_uri = error.create_uri(redirect_uri, state)
        expected_uri = '{}#error={}&error_description={}&state={}' \
            .format(redirect_uri, self.error, self.desc, state)
        compare(expected_uri, created_uri)
