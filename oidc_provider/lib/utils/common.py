from django.core.urlresolvers import reverse

from oidc_provider import settings


def get_issuer():
	"""
	Construct the issuer full url. Basically is the site url with some path
	appended.
	"""
	site_url = settings.get('SITE_URL')
	path = reverse('oidc_provider:provider_info') \
		.split('/.well-known/openid-configuration/')[0]
	issuer = site_url + path

	return issuer
