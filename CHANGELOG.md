# CHANGELOG

All notable changes to this project will be documented in this file.

### [Unreleased]

### [0.0.4] - 2015-04-22

#### Added
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
