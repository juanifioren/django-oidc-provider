import os
from setuptools import setup


# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-oidc-provider',
    version='0.3.6',
    packages=[
        'oidc_provider', 'oidc_provider/lib', 'oidc_provider/lib/endpoints',
        'oidc_provider/lib/utils', 'oidc_provider/tests', 'oidc_provider/tests/app',
        'oidc_provider/migrations', 'oidc_provider/management', 'oidc_provider/management/commands',
    ],
    include_package_data=True,
    license='MIT License',
    description='OpenID Connect Provider implementation for Django.',
    long_description='http://github.com/juanifioren/django-oidc-provider',
    url='http://github.com/juanifioren/django-oidc-provider',
    author='Juan Ignacio Fiorentino',
    author_email='juanifioren@gmail.com',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
    tests_require=[
        'pyjwkest==1.1.0',
        'mock==1.3.0',
    ],
    extras_require={
        'pyjwkest': ['pyjwkest==1.1.0'],
        'jose': ['python-jose==1.0.0'],
    }
)
