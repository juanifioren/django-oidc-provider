# CHANGELOG

All notable changes to this project will be documented in this file.

### [Unreleased]

### [0.1.2] - 2015-08-04

##### Added
- Add token_endpoint_auth_methods_supported to discovery.

##### Fixed
- Missing commands folder in setup file.

### [0.1.1] - 2015-07-31

##### Added
- Sending access_token as query string parameter in UserInfo Endpoint.
- Support HTTP Basic client authentication.

##### Changed
- Use models setting instead of User.

##### Fixed
- In python 2: "aud" and "nonce" parameters didn't appear in id_token.

### [0.1.0] - 2015-07-17

##### Added
- Now id tokens are signed/encrypted with RS256.
- Command for easily generate random RSA key.
- Jwks uri to discovery endpoint.
- id_token_signing_alg_values_supported to discovery endpoint.

##### Fixed
- Nonce support for both Code and Implicit flow.

### [0.0.7] - 2015-07-06

##### Added
- Support for Python 3.
- Way of remember user consent and skipt it (OIDC_SKIP_CONSENT_ENABLE).
- Setting OIDC_SKIP_CONSENT_EXPIRE.

##### Changed
- Now OIDC_EXTRA_SCOPE_CLAIMS must be a string, to be lazy imported.

### [0.0.6] - 2015-06-16

##### Added
- Better naming for models in the admin.

##### Changed
- Now tests run without the need of a project configured.

##### Fixed
- Error when returning address_formatted claim.

### [0.0.5] - 2015-05-09

##### Added
- Support for Django 1.8.

##### Fixed
- Validation of scope in UserInfo endpoint.

### [0.0.4] - 2015-04-22

##### Added
- Initial migrations.

##### Fixed
- Important bug with id_token when using implicit flow.
- Validate Code expiration in Auth Code Flow.
- Validate Access Token expiration in UserInfo endpoint.

### [0.0.3] - 2015-04-15

##### Added
- Normalize gender field in UserInfo.

##### Changed
- Make address_formatted a property inside UserInfo.

##### Fixed
- Important bug in claims response.

### [0.0.2] - 2015-03-26

##### Added
- Setting OIDC_AFTER_USERLOGIN_HOOK.

##### Fixed
- Tests failing because an incorrect tag in one template.

### [0.0.1] - 2015-03-13

##### Added
- Provider Configuration Information endpoint.
- Setting OIDC_IDTOKEN_SUB_GENERATOR.

##### Changed
- Now use setup in OIDC_EXTRA_SCOPE_CLAIMS setting.

### [0.0.0] - 2015-02-26
