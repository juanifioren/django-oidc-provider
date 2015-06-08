from datetime import timedelta

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

SITE_ID = 1

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
)


INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.admin',

    'oidc_provider',
)

SECRET_KEY = 'secret-for-test-secret-secret'

ROOT_URLCONF = 'oidc_provider.tests.test_urls'

TEMPLATE_DIRS = (
    "oidc_provider/tests/templates",
)

# OIDC Provider settings.

SITE_URL = 'http://localhost:8000'