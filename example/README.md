# Example Project

On this example you'll be running your own OIDC provider in a second. This is a Django app with all the necessary things to work with `django-oidc-provider` package.

## Setup & running using Docker

Build and run the container.

```bash
$ docker build -t django-oidc-provider .
$ docker run -p 8000:8000 --name django-oidc-provider-app django-oidc-provider
```

Go to http://localhost:8000/ and create your Client.

## Install package for development

After you run `pip install -r requirements.txt`.
```bash
# Remove pypi package.
$ pip uninstall django-oidc-provider

# Go back to django-oidc-provider/ folder and add the package on editable mode.
$ cd ..
$ pip install -e .
```
