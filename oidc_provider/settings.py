from django.conf import settings
from oidc_provider.lib.claims import AbstractScopeClaims


# Here goes all the package default settings.

default_settings = {
	# Required.
	'LOGIN_URL': None,
	'SITE_URL': None,

	# Optional.
	'OIDC_CODE_EXPIRE': 60*10,
	'OIDC_EXTRA_SCOPE_CLAIMS': AbstractScopeClaims,
	'OIDC_IDTOKEN_EXPIRE': 60*10,
	'OIDC_TOKEN_EXPIRE': 60*60,
}

def get(name):
	'''
	Helper function to use inside the package.
	'''
	try:
		value = default_settings[name]
		value = getattr(settings, name)
	except AttributeError:
		if value == None:
			raise Exception('You must set ' + name + ' in your settings.')

	return value
