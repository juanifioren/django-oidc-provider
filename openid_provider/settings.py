from django.conf import settings


class default_settings(object):

	# Here goes all the package default settings.

	LOGIN_URL = None

	SITE_URL = None

def get(name):
	'''
	Helper function to use inside the package.
	'''
	try:
		value = getattr(default_settings, name)
		value = getattr(settings, name)
	except AttributeError:
		if value == None:
			raise Exception('You must set ' + name + ' in your settings.')

	return value
