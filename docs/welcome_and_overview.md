# Introduction

Welcome to the documentation repository for Relapse, a 
[Matrix](https://matrix.org) homeserver implementation developed by the matrix.org core 
team.

## Installing and using Relapse

This documentation covers topics for **installation**, **configuration** and
**maintenance** of your Relapse process:

* Learn how to [install](setup/installation.md) and
  [configure](usage/configuration/config_documentation.md) your own instance, perhaps with [Single
  Sign-On](usage/configuration/user_authentication/index.html).

* See how to [upgrade](upgrade.md) between Relapse versions.

* Administer your instance using the [Admin
  API](usage/administration/admin_api/index.html), installing [pluggable
  modules](modules/index.html), or by accessing the [manhole](manhole.md).

* Learn how to [read log lines](usage/administration/request_log.md), configure
  [logging](usage/configuration/logging_sample_config.md) or set up [structured
  logging](structured_logging.md).

* Scale Relapse through additional [worker processes](workers.md).

* Set up [monitoring and metrics](metrics-howto.md) to keep an eye on your
  Relapse instance's performance.

## Developing on Relapse

Contributions are welcome! Relapse is primarily written in
[Python](https://python.org). As a developer, you may be interested in the
following documentation:

* Read the [Contributing Guide](development/contributing_guide.md). It is meant
  to walk new contributors through the process of developing and submitting a
  change to the Relapse codebase (which is [hosted on
  GitHub](https://github.com/clokep/relapse)).

* Set up your [development
  environment](development/contributing_guide.md#2-what-do-i-need), then learn
  how to [lint](development/contributing_guide.md#run-the-linters) and
  [test](development/contributing_guide.md#8-test-test-test) your code.

* Look at [the issue tracker](https://github.com/clokep/relapse/issues) for
  bugs to fix or features to add. If you're new, it may be best to start with
  those labeled [good first
  issue](https://github.com/clokep/relapse/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).

* Understand [how Relapse is
  built](development/internal_documentation/index.html), how to [migrate
  database schemas](development/database_schema.md), learn about
  [federation](federate.md) and how to [set up a local
  federation](federate.md#running-a-demo-federation-of-relapses) for development.

* We like to keep our `git` history clean. [Learn](development/git.md) how to
  do so!

* And finally, contribute to this documentation! The source for which is
  [located here](https://github.com/clokep/relapse/tree/develop/docs).

## Donating to Relapse development

Want to help keep Relapse going but don't know how to code? Relapse is a
[Matrix.org Foundation](https://matrix.org) project. Consider becoming a
supporter on [Liberapay](https://liberapay.com/matrixdotorg),
[Patreon](https://patreon.com/matrixdotorg) or through
[PayPal](https://paypal.me/matrixdotorg) via a one-time donation.

If you are an organisation or enterprise and would like to sponsor development,
reach out to us over email at: support (at) matrix.org

## Reporting a security vulnerability

If you've found a security issue in Relapse or any other Matrix.org Foundation
project, please report it to us in accordance with our [Security Disclosure
Policy](https://www.matrix.org/security-disclosure-policy/). Thank you!
