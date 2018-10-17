.. _changelog:

Changelog
#########

All notable changes to this project will be documented in this file.

Unreleased
==========

0.7.0
=====

*2018-10-17*

* Added: support multiple response types per client.
* Added: make version available in code.
* Added: token introspection docs.
* Changed: drop support for Django versions lower than 1.11.
* Changed: create RSA key command. Increment key size to 2048.
* Fixed: OIDC_IDTOKEN_INCLUDE_CLAIMS used with custom claims setting.
* Fixed: bug in prompt parameter (with space-separated values).

0.6.2
=====

*2018-08-03*

* Added: support introspection on client credentials tokens.
* Changed: accept lowercase "bearer" in Authorization header.
* Fixed: ScopeClaims class.
* Fixed: code is not zip safe.

0.6.1
=====

*2018-07-10*

* Added: token instrospection endpoint support (RFC7662).
* Added: request in password grant authenticate call.
* Changed: dropping support for Django versions before 1.8.
* Changed: pass token and request to OIDC_IDTOKEN_PROCESSING_HOOK.
* Fixed: CORS OPTIONS request blocked on userinfo request.
* Fixed: settings to support falsy valued overrides.
* Fixed: token introspection "aud" and "client_id" response.
* Fixed: Token Model str() crashes when using client credentials grant.

0.6.0
=====

*2018-04-13*

* Added: OAuth2 grant_type client_credentials support.
* Added: pep8 compliance and checker.
* Added: Setting OIDC_IDTOKEN_INCLUDE_CLAIMS supporting claims inside id_token.
* Changed: Test suit now uses pytest.
* Fixed: Infinite callback loop in the check-session iframe.

0.5.3
=====

*2018-03-09*

* Fixed: Update project to support Django 2.0

0.5.2
=====

*2017-08-22*

* Fixed: infinite login loop if "prompt=login" (#198)
* Fixed: Django 2.0 deprecation warnings (#185)

0.5.1
=====

*2017-07-11*

* Changed: Documentation template changed to Read The Docs.
* Fixed: install_requires has not longer pinned versions.
* Fixed: Removed infinity loop during authorization stage when prompt=login has been send.
* Fixed: Changed prompt handling as set of options instead of regular string.
* Fixed: Redirect URI must match exactly with given in query parameter.
* Fixed: Stored user consent are useful for public clients too.
* Fixed: documentation for custom scopes handling.
* Fixed: Scopes during refresh and code exchange are being taken from authorization request and not from query parameters.

0.5.0
=====

*2017-05-18*

* Added: signals when user accept/decline the authorization page.
* Added: OIDC_AFTER_END_SESSION_HOOK setting for additional business logic.
* Added: feature granttype password.
* Added: require_consent and reuse_consent are added to Client model.
* Changed: OIDC_SKIP_CONSENT_ALWAYS and OIDC_SKIP_CONSENT_ENABLE are removed from settings.
* Fixed: timestamps with unixtime (instead of django timezone).
* Fixed: field refresh_token cannot be primary key if null.
* Fixed: create_uri_exceptions are now being logged at Exception level not DEBUG.

0.4.4
=====

*2016-11-29*

* Fixed: Bug in Session Management middleware when using Python 3.
* Fixed: Translations handling.

0.4.3
=====

*2016-11-02*

* Added: Session Management 1.0 support.
* Added: post_logout_redirect_uris into admin.
* Changed: Package url names.
* Changed: Rename /logout/ url to /end-session/.
* Fixed: bug when trying authorize with response_type id_token without openid scope.

0.4.2
=====

*2016-10-13*

* Added: support for client redirect URIs with query strings.
* Fixed: bug when generating secret_key value using admin.
* Changed: client is available to OIDC_EXTRA_SCOPE_CLAIMS implementations via self.client.
* Changed: the constructor signature for ScopeClaims has changed, it now is called with the Token as its single argument.

0.4.1
=====

*2016-10-03*

* Changed: update pyjwkest to version 1.3.0.
* Changed: use Cryptodome instead of Crypto lib.

0.4.0
=====

*2016-09-12*

* Added: support for Hybrid Flow.
* Added: new attributes for Clients: Website url, logo, contact email, terms url.
* Added: polish translations.
* Added: examples section in documentation.
* Fixed: CORS in discovery and userinfo endpoint.
* Fixed: client type public bug when created using the admin.
* Fixed: missing OIDC_TOKEN_EXPIRE setting on implicit flow.

0.3.7
=====

*2016-08-31*

* Added: support for Django 1.10.
* Added: initial translation files (ES, FR).
* Added: support for at_hash parameter.
* Fixed: empty address dict in userinfo response.

0.3.6
=====

*2016-07-07*

* Changed: OIDC_USERINFO setting.

0.3.5
=====

*2016-06-21*

* Added: field date_given in UserConsent model.
* Added: verbose names to all model fields.
* Added: customize scopes names and descriptions on authorize template.
* Changed: OIDC_EXTRA_SCOPE_CLAIMS setting.

0.3.4
=====

*2016-06-10*

* Changed: Make SITE_URL setting optional.
* Fixed: Missing migration.

0.3.3
=====

*2016-05-03*

* Fixed: Important bug with PKCE and form submit in Auth Request.

0.3.2
=====

*2016-04-26*

* Added: choose type of client on creation.
* Added: implement Proof Key for Code Exchange by OAuth Public Clients.
* Added: support for prompt parameter.
* Added: support for different client JWT tokens algorithm.
* Fixed: not auto-approve requests for non-confidential clients (publics).

0.3.1
=====

*2016-03-09*

* Fixed: response_type was not being validated (OpenID request).

0.3.0
=====

*2016-02-23*

* Added: support OAuth2 requests.
* Added: decorator for protecting views with OAuth2.
* Added: setting OIDC_IDTOKEN_PROCESSING_HOOK.

0.2.5
=====

*2016-02-03*

* Added: Setting OIDC_SKIP_CONSENT_ALWAYS.
* Changed: Removing OIDC_RSA_KEY_FOLDER setting. Moving RSA Keys to the database.
* Changed: Update pyjwkest to version 1.1.0.
* Fixed: Nonce parameter missing on the decide form.
* Fixed: Set Allow-Origin header to jwks endpoint.

0.2.4
=====

*2016-01-20*

* Added: Auto-generation of client ID and SECRET using the admin.
* Added: Validate nonce parameter when using Implicit Flow.
* Fixed: generating RSA key by ignoring value of OIDC_RSA_KEY_FOLDER.
* Fixed: make OIDC_AFTER_USERLOGIN_HOOK and OIDC_IDTOKEN_SUB_GENERATOR to be lazy imported by the location of the function.
* Fixed: problem with a function that generate urls for the /.well-known/openid-configuration/ endpoint.

0.2.3
=====

*2016-01-06*

* Added: Make user and client unique on UserConsent model.
* Added: Support for URL's without end slash.
* Changed: Upgrade pyjwkest to version 1.0.8.
* Fixed: String format error in models.
* Fixed: Redirect to non http urls fail (for Mobile Apps).

0.2.1
=====

*2015-10-21*

* Added: refresh token flow.
* Changed: upgrade pyjwkest to version >= 1.0.6.
* Fixed: Unicode error in Client model.
* Fixed: Bug in creatersakey command (when using Python 3).
* Fixed: Bug when updating pyjwkest version.

0.2.0
=====

*2015-09-25*

* Changed: UserInfo model was removed. Now you can add your own model using OIDC_USERINFO setting.
* Fixed: ID token does NOT contain kid.

0.1.2
=====

*2015-08-04*

* Added: add token_endpoint_auth_methods_supported to discovery.
* Fixed: missing commands folder in setup file.

0.1.1
=====

*2015-07-31*

* Added: sending access_token as query string parameter in UserInfo Endpoint.
* Added: support HTTP Basic client authentication.
* Changed: use models setting instead of User.
* Fixed: in python 2: "aud" and "nonce" parameters didn't appear in id_token.

0.1.0
=====

*2015-07-17*

* Added: now id tokens are signed/encrypted with RS256.
* Added: command for easily generate random RSA key.
* Added: jwks uri to discovery endpoint.
* Added: id_token_signing_alg_values_supported to discovery endpoint.
* Fixed: nonce support for both Code and Implicit flow.

0.0.7
=====

*2015-07-06*

****

* Added: support for Python 3.
* Added: way of remember user consent and skipt it (OIDC_SKIP_CONSENT_ENABLE).
* Added: setting OIDC_SKIP_CONSENT_EXPIRE.
* Changed: now OIDC_EXTRA_SCOPE_CLAIMS must be a string, to be lazy imported.

0.0.6
=====

*2015-06-16*

* Added: better naming for models in the admin.
* Changed: now tests run without the need of a project configured.
* Fixed: error when returning address_formatted claim.

0.0.5
=====

*2015-05-09*

* Added: support for Django 1.8.
* Fixed: validation of scope in UserInfo endpoint.

0.0.4
=====

*2015-04-22*

* Added: initial migrations.
* Fixed: important bug with id_token when using implicit flow.
* Fixed: validate Code expiration in Auth Code Flow.
* Fixed: validate Access Token expiration in UserInfo endpoint.

0.0.3
=====

*2015-04-15*

* Added: normalize gender field in UserInfo.
* Changed: make address_formatted a property inside UserInfo.
* Fixed: important bug in claims response.

0.0.2
=====

*2015-03-26*

* Added: setting OIDC_AFTER_USERLOGIN_HOOK.
* Fixed: tests failing because an incorrect tag in one template.

0.0.1
=====

*2015-03-13*

* Added: provider Configuration Information endpoint.
* Added: setting OIDC_IDTOKEN_SUB_GENERATOR.
* Changed: now use setup in OIDC_EXTRA_SCOPE_CLAIMS setting.

0.0.0
=====

*2015-02-26*
