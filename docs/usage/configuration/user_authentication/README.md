# User Authentication

Relapse supports multiple methods of authenticating users, either out-of-the-box or through custom pluggable
authentication modules.

Included in Relapse is support for authenticating users via:

* A username and password.
* An email address and password.
* Single Sign-On through the SAML, Open ID Connect or CAS protocols.
* JSON Web Tokens.
* An administrator's shared secret.

Relapse can additionally be extended to support custom authentication schemes through optional "password auth provider"
modules.