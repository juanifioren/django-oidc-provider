.. _contribute:

Contribute
##########

We love contributions, so please feel free to fix bugs, improve things, provide documentation. These are the steps:

* Create an issue and explain your feature/bugfix.
* Wait collaborators comments.
* Fork the project and create new branch from ``develop``.
* Make your feature addition or bug fix.
* Add tests and documentation if needed.
* Create pull request for the issue to the ``develop`` branch.
* Wait collaborators reviews.

Running Tests
=============

Use `tox <https://pypi.python.org/pypi/tox>`_ for running tests in each of the environments, also to run coverage and flake8 among::

    # Run all tests.
    $ tox

    # Run with Python 3.11 and Django 4.2.
    $ tox -e py311-django42

    # Run single test file on specific environment.
    $ tox -e py311-django42 -- tests/cases/test_authorize_endpoint.py

We use `Github Actions <https://github.com/juanifioren/django-oidc-provider/actions>`_ to automatically test every commit to the project.

Improve Documentation
=====================

We use `Sphinx <http://www.sphinx-doc.org/>`_ to generate this documentation. If you want to add or modify something just:

* Install Sphinx (``pip install sphinx``) and the auto-build tool (``pip install sphinx-autobuild``).
* Move inside the docs folder. ``cd docs/``
* Generate and watch docs by running ``sphinx-autobuild . _build/``.
* Open ``http://127.0.0.1:8000`` in a browser.
