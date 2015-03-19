# Example Django App

This is just a simple Django app with all the necessary things to work with `django-oidc-provider` package.

## Setup & Running

Setup project environment with [virtualenv](https://virtualenv.pypa.io) and [pip](https://pip.pypa.io).

```bash
$ virtualenv project_env
$ source project_env/bin/activate
$ git clone https://github.com/juanifioren/django-oidc-provider.git
$ cd django-oidc-provider/example_app
$ pip install -r requirements.txt
```

Run your provider.

```bash
$ python manage.py makemigrations
$ python manage.py migrate
$ python manage.py runserver
```