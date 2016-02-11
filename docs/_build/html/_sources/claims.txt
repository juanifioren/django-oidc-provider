.. _claims:

Standard Claims
###############

This subset of OpenID Connect defines a set of standard Claims. They are returned in the UserInfo Response.

The package comes with a setting called ``OIDC_USERINFO``, basically it refers to a class that MUST have a class-method named ``get_by_user``, this will be called with a Django ``User`` instance and returns an object with all the claims of the user as attributes.

List of all the attributes grouped by scopes:

+--------------------+----------------+-----------------------+------------------------+
| profile            | email          | phone                 | address                |
+====================+================+=======================+========================+
| name               | email          | phone_number          | address_formatted      |
+--------------------+----------------+-----------------------+------------------------+
| given_name         | email_verified | phone_number_verified | address_street_address |
+--------------------+----------------+-----------------------+------------------------+
| family_name        |                |                       | address_locality       |
+--------------------+----------------+-----------------------+------------------------+
| middle_name        |                |                       | address_region         |
+--------------------+----------------+-----------------------+------------------------+
| nickname           |                |                       | address_postal_code    |
+--------------------+----------------+-----------------------+------------------------+
| preferred_username |                |                       | address_country        |
+--------------------+----------------+-----------------------+------------------------+
| profile            |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| picture            |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| website            |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| gender             |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| birthdate          |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| zoneinfo           |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| locale             |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+
| updated_at         |                |                       |                        |
+--------------------+----------------+-----------------------+------------------------+

Example using a django model::

	from django.conf import settings
	from django.db import models


	class UserInfo(models.Model):

	    GENDER_CHOICES = [
	        ('F', 'Female'),
	        ('M', 'Male'),
	    ]

	    user = models.OneToOneField(settings.AUTH_USER_MODEL, primary_key=True)
	    
	    given_name = models.CharField(max_length=255, blank=True, null=True)
	    family_name = models.CharField(max_length=255, blank=True, null=True)
	    gender = models.CharField(max_length=100, choices=GENDER_CHOICES, null=True)
	    birthdate = models.DateField(null=True)
	    updated_at = models.DateTimeField(auto_now=True, null=True)

	    email_verified = models.NullBooleanField(default=False)

	    phone_number = models.CharField(max_length=255, blank=True, null=True)
	    phone_number_verified = models.NullBooleanField(default=False)

	    address_locality = models.CharField(max_length=255, blank=True, null=True)
	    address_country = models.CharField(max_length=255, blank=True, null=True)

	    @classmethod
	    def get_by_user(cls, user):
	        return cls.objects.get(user=user)
