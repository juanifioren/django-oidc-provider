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

    # Run all tests.
    $ tox

    # Run with Python 2.7 and Django 1.9.
    $ tox -e py27-django19

    # Run single test file.
    $ python runtests.py oidc_provider.tests.test_authorize_endpoint

Also tests run on every commit to the project, we use `travis <https://travis-ci.org/juanifioren/django-oidc-provider/>`_ for this.

Improve Documentation
=====================

We use `Sphinx <http://www.sphinx-doc.org/>`_ for generate this documentation. I you want to add or modify something just:

* Install Sphinx (``pip install sphinx``) and the auto-build tool (``pip install sphinx-autobuild``).
* Move inside the docs folder. ``cd docs/``
* Generate and watch docs by running ``sphinx-autobuild . _build/``.
* Open ``http://127.0.0.1:8000`` on a browser.
