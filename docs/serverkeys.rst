.. _serverkeys:

Server Keys
###########

Server RSA keys are used to sign/encrypt ID Tokens. These keys are stored in the ``RSAKey`` model. So the package will automatically generate public keys and expose them in the ``jwks_uri`` endpoint.

You can easily create them with the admin:

.. image:: http://i64.tinypic.com/vj2ma.png
    :align: center

Or by using ``python manage.py creatersakey`` command.

Here is an example response from the ``jwks_uri`` endpoint::

    GET /openid/jwks HTTP/1.1
    Host: localhost:8000

    {  
      "keys":[  
        {  
          "use":"sig",
          "e":"AQAB",
          "kty":"RSA",
          "alg":"RS256",
          "n":"3Gm0pS7ij_SnY96wkbaki74MUYJrobXecO6xJhvmAEEhMHGpO0m4H2nbOWTf6Jc1FiiSvgvhObVk9xPOM6qMTQ5D5pfWZjNk99qDJXvAE4ImM8S0kCaBJGT6e8JbuDllCUq8aL71t67DhzbnoBsKCnVOE1GJffpMcDdBUYkAsx8",
          "kid":"a38ea7fbf944cc060eaf5acc1956b0e3"
        }
      ]
    }
