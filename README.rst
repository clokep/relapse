=========================================================================
Relapse |support| |development| |documentation| |license| |pypi| |python|
=========================================================================

Relapse is a fork of `Synapse <https://github.com/matrix-org/synapse>`_, a homeserver for
the `Matrix <https://matrix.org/>`_ protocol.

The primary goal of this fork is to make things simpler, more modern, and easier
to maintain. With that in mind, **a number of features have been removed**.

.. contents::

Installing and configuration
============================

The Relapse documentation describes `how to install Relapse <https://clokep.github.io/relapse/latest/setup/installation.html>`_. We recommend using
`Docker images <https://clokep.github.io/relapse/latest/setup/installation.html#docker-images-and-ansible-playbooks>`_.

.. _federation:

Relapse has a variety of `config options
<https://clokep.github.io/relapse/latest/usage/configuration/config_documentation.html>`_
which can be used to customise its behaviour after installation.
There are additional details on how to `configure Relapse for federation here
<https://clokep.github.io/relapse/latest/federate.html>`_.

.. _reverse-proxy:

Using a reverse proxy with Relapse
----------------------------------

It is recommended to put a reverse proxy such as
`nginx <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>`_,
`Apache <https://httpd.apache.org/docs/current/mod/mod_proxy_http.html>`_,
`Caddy <https://caddyserver.com/docs/quick-starts/reverse-proxy>`_,
`HAProxy <https://www.haproxy.org/>`_ or
`relayd <https://man.openbsd.org/relayd.8>`_ in front of Relapse. One advantage of
doing so is that it means that you can expose the default https port (443) to
Matrix clients without needing to run Relapse with root privileges.
For information on configuring one, see `the reverse proxy docs
<https://clokep.github.io/relapse/latest/reverse_proxy.html>`_.

Upgrading an existing Relapse
-----------------------------

The instructions for upgrading Relapse are in `the upgrade notes`_.
Please check these instructions as upgrading may require extra steps for some
versions of Relapse.

.. _the upgrade notes: https://clokep.github.io/relapse/develop/upgrade.html


Platform dependencies
---------------------

Relapse uses a number of platform dependencies such as Python and PostgreSQL,
and aims to follow supported upstream versions. See the
`deprecation policy <https://clokep.github.io/relapse/latest/deprecation_policy.html>`_
for more details.


Security note
-------------

Matrix serves raw, user-supplied data in some APIs -- specifically the `content
repository endpoints`_.

.. _content repository endpoints: https://matrix.org/docs/spec/client_server/latest.html#get-matrix-media-r0-download-servername-mediaid

Whilst we make a reasonable effort to mitigate against XSS attacks (for
instance, by using `CSP`_), a Matrix homeserver should not be hosted on a
domain hosting other web applications. This especially applies to sharing
the domain with Matrix web clients and other sensitive applications like
webmail. See
https://developer.github.com/changes/2014-04-25-user-content-security for more
information.

.. _CSP: https://github.com/matrix-org/synapse/pull/1021

Ideally, the homeserver should not simply be on a different subdomain, but on
a completely different `registered domain`_ (also known as top-level site or
eTLD+1). This is because `some attacks`_ are still possible as long as the two
applications share the same registered domain.

.. _registered domain: https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-03#section-2.3

.. _some attacks: https://en.wikipedia.org/wiki/Session_fixation#Attacks_using_cross-subdomain_cookie

To illustrate this with an example, if your Element Web or other sensitive web
application is hosted on ``A.example1.com``, you should ideally host Relapse on
``example2.com``. Some amount of protection is offered by hosting on
``B.example1.com`` instead, so this is also acceptable in some scenarios.
However, you should *not* host your Relapse on ``A.example1.com``.

Note that all of the above refers exclusively to the domain used in Relapse's
``public_baseurl`` setting. In particular, it has no bearing on the domain
mentioned in MXIDs hosted on that server.

Following this advice ensures that even if an XSS is found in Relapse, the
impact to other applications will be minimal.


Testing a new installation
==========================

The easiest way to try out your new Relapse installation is by connecting to it
from a web client.

Unless you are running a test instance of Relapse on your local machine, in
general, you will need to enable TLS support before you can successfully
connect from a client: see
`TLS certificates <https://clokep.github.io/relapse/latest/setup/installation.html#tls-certificates>`_.

An easy way to get started is to login or register via Element at
https://app.element.io/#/login or https://app.element.io/#/register respectively.
You will need to change the server you are logging into from ``matrix.org``
and instead specify a Homeserver URL of ``https://<server_name>:8448``
(or just ``https://<server_name>`` if you are using a reverse proxy).
If you prefer to use another client, refer to our
`client breakdown <https://matrix.org/ecosystem/clients/>`_.

If all goes well you should at least be able to log in, create a room, and
start sending messages.

.. _`client-user-reg`:

Registering a new user from a client
------------------------------------

By default, registration of new users via Matrix clients is disabled. To enable
it:

1. In the
   `registration config section <https://clokep.github.io/relapse/latest/usage/configuration/config_documentation.html#registration>`_
   set ``enable_registration: true`` in ``homeserver.yaml``.
2. Then **either**:

   a. set up a `CAPTCHA <https://clokep.github.io/relapse/latest/CAPTCHA_SETUP.html>`_, or
   b. set ``enable_registration_without_verification: true`` in ``homeserver.yaml``.

We **strongly** recommend using a CAPTCHA, particularly if your homeserver is exposed to
the public internet. Without it, anyone can freely register accounts on your homeserver.
This can be exploited by attackers to create spambots targetting the rest of the Matrix
federation.

Your new user name will be formed partly from the ``server_name``, and partly
from a localpart you specify when you create the account. Your name will take
the form of::

    @localpart:my.domain.name

(pronounced "at localpart on my dot domain dot name").

As when logging in, you will need to specify a "Custom server".  Specify your
desired ``localpart`` in the 'User name' box.

Troubleshooting and support
===========================

The `Admin FAQ <https://clokep.github.io/relapse/latest/usage/administration/admin_faq.html>`_
includes tips on dealing with some common problems. For more details, see
`Relapse's wider documentation <https://clokep.github.io/relapse/latest/>`_.

For additional support installing or managing Relapse, please ask in the community
support room |room|_ (from a matrix.org account if necessary). We do not use GitHub
issues for support requests, only for bug reports and feature requests.

.. |room| replace:: ``#relapse:matrix.org``
.. _room: https://matrix.to/#/#relapse:matrix.org

.. |docs| replace:: ``docs``
.. _docs: docs

Identity Servers
================

Identity servers have the job of mapping email addresses and other 3rd Party
IDs (3PIDs) to Matrix user IDs, as well as verifying the ownership of 3PIDs
before creating that mapping.

**They are not where accounts or credentials are stored - these live on home
servers. Identity Servers are just for mapping 3rd party IDs to matrix IDs.**

This process is very security-sensitive, as there is obvious risk of spam if it
is too easy to sign up for Matrix accounts or harvest 3PID data. In the longer
term, we hope to create a decentralised system to manage it (`matrix-doc #712
<https://github.com/matrix-org/matrix-doc/issues/712>`_), but in the meantime,
the role of managing trusted identity in the Matrix ecosystem is farmed out to
a cluster of known trusted ecosystem partners, who run 'Matrix Identity
Servers' such as `Sydent <https://github.com/matrix-org/sydent>`_, whose role
is purely to authenticate and track 3PID logins and publish end-user public
keys.

You can host your own copy of Sydent, but this will prevent you reaching other
users in the Matrix ecosystem via their email address, and prevent them finding
you. We therefore recommend that you use one of the centralised identity servers
at ``https://matrix.org`` or ``https://vector.im`` for now.

To reiterate: the Identity server will only be used if you choose to associate
an email address with your account, or send an invite to another user via their
email address.


Development
===========

We welcome contributions to Relapse from the community!
The best place to get started is our
`guide for contributors <https://clokep.github.io/relapse/latest/development/contributing_guide.html>`_.
This is part of our larger `documentation <https://clokep.github.io/relapse/latest>`_, which includes

information for Relapse developers as well as Relapse administrators.
Developers might be particularly interested in:

* `Relapse's database schema <https://clokep.github.io/relapse/latest/development/database_schema.html>`_,
* `notes on Relapse's implementation details <https://clokep.github.io/relapse/latest/development/internal_documentation/index.html>`_, and
* `how we use git <https://clokep.github.io/relapse/latest/development/git.html>`_.

Alongside all that, join our developer community on Matrix:
`#relapse:matrix.org <https://matrix.to/#/#relapse:matrix.org>`_, featuring real humans!


.. |support| image:: https://img.shields.io/matrix/relapse:matrix.org?label=support&logo=matrix
  :alt: (get support on #relapse:matrix.org)
  :target: https://matrix.to/#/#relapse:matrix.org

.. |development| image:: https://img.shields.io/matrix/relapse:matrix.org?label=development&logo=matrix
  :alt: (discuss development on #relapse:matrix.org)
  :target: https://matrix.to/#/#relapse:matrix.org

.. |documentation| image:: https://img.shields.io/badge/documentation-%E2%9C%93-success
  :alt: (Rendered documentation on GitHub Pages)
  :target: https://clokep.github.io/relapse/latest/

.. |license| image:: https://img.shields.io/github/license/clokep/relapse
  :alt: (check license in LICENSE file)
  :target: LICENSE

.. |pypi| image:: https://img.shields.io/pypi/v/matrix-relapse
  :alt: (latest version released on PyPi)
  :target: https://pypi.org/project/matrix-relapse

.. |python| image:: https://img.shields.io/pypi/pyversions/matrix-relapse
  :alt: (supported python versions)
  :target: https://pypi.org/project/matrix-relapse
