# Example Project

![Example Project](http://s12.postimg.org/e4uwlsi0d/Screenshot_from_2016_02_02_13_15_26.png)

Run your own OIDC provider in a second. This is a Django app with all the necessary things to work with `django-oidc-provider` package.

## Setup & Running

- [Manually](#manually)
- [Using Docker](#using-docker)

### Manually

Setup project environment with [virtualenv](https://virtualenv.pypa.io) and [pip](https://pip.pypa.io).

```bash
# For Python 2.7.
$ virtualenv project_env
# Or Python 3.
$ virtualenv -p /usr/bin/python3.4 project_env

$ source project_env/bin/activate

$ git clone https://github.com/juanifioren/django-oidc-provider.git
$ cd django-oidc-provider/example_project
$ pip install -r requirements.txt
```

Run your provider.

```bash
$ python manage.py migrate
$ python manage.py creatersakey
$ python manage.py runserver
```

Open your browser and go to `http://localhost:8000`. Voilà!

### Using Docker

Build and run the container.

```bash
$ docker build -t django-oidc-provider .
$ docker run -d -p 8000:8000 django-oidc-provider
```

## Install package for development

After you run `pip install -r requirements.txt`.
```bash
# Remove pypi package.
$ pip uninstall django-oidc-provider

# Go back and add the package again.
$ cd ..
$ pip install -e .
```
