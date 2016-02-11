.. _contribute:

Contribute
##########

We love contributions, so please feel free to fix bugs, improve things, provide documentation. You SHOULD follow this steps:

* Fork the project.
* Make your feature addition or bug fix.
* Add tests for it inside ``oidc_provider/tests``. Then run all and ensure everything is OK (read docs for how to test in all envs). 
* Send pull request to the specific version branch.

Running Tests
=============

Use `tox <https://pypi.python.org/pypi/tox>`_ for running tests in each of the environments, also to run coverage among::

    $ tox

If you have a Django project properly configured with the package. Then just run tests as normal::

    $ python manage.py test --settings oidc_provider.tests.app.settings oidc_provider

Also tests run on every commit to the project, we use `travis <https://travis-ci.org/juanifioren/django-oidc-provider/>`_ for this.
