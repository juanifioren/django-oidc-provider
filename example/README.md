# Example Project

![Example Project](https://s17.postimg.org/4jjj8lavj/Screen_Shot_2016_09_07_at_15_58_43.png)

On this example you'll be running your own OIDC provider in a second. This is a Django app with all the necessary things to work with `django-oidc-provider` package.

## Setup & Running

- [Manually](#manually)
- [Using Docker](#using-docker)

### Manually

Setup project environment with [virtualenv](https://virtualenv.pypa.io) and [pip](https://pip.pypa.io).

```bash
$ virtualenv -p /usr/bin/python3 project_env

$ source project_env/bin/activate

$ git clone https://github.com/juanifioren/django-oidc-provider.git
$ cd django-oidc-provider/example
$ pip install -r requirements.txt
```

Run your provider.

```bash
$ python manage.py migrate
$ python manage.py creatersakey
$ python manage.py createsuperuser
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

# Go back to django-oidc-provider/ folder and add the package on editable mode.
$ cd ..
$ pip install -e .
```
