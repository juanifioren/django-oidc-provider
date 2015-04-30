# Example Project

Run your own OIDC provider in a second. This is a Django app with all the necessary things to work with `django-oidc-provider` package.

## Setup & Running

Setup project environment with [virtualenv](https://virtualenv.pypa.io) and [pip](https://pip.pypa.io).

```bash
$ virtualenv project_env
$ source project_env/bin/activate

$ git clone https://github.com/juanifioren/django-oidc-provider.git
$ cd django-oidc-provider/example_project
$ pip install -r requirements.txt
```

Run your provider.

```bash
$ python manage.py migrate
$ python manage.py runserver
```
