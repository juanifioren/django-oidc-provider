import os
from datetime import timedelta


DEBUG = False

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

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'oidc_provider': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'DEBUG'),
        },
    },
}

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.admin',

    'oidc_provider',
)

SECRET_KEY = 'this-is-top-secret'

ROOT_URLCONF = 'oidc_provider.tests.app.urls'

TEMPLATE_DIRS = (
    "oidc_provider/tests/templates",
)

# OIDC Provider settings.

SITE_URL = 'http://localhost:8000'
OIDC_RSA_KEY_FOLDER = os.path.dirname(__file__)
OIDC_USERINFO = 'oidc_provider.tests.app.utils.FakeUserInfo'
