# Relapse Release Cycle

Releases of Relapse follow a two week release cycle with new releases usually
occurring on Tuesdays:

* Day 0: Relapse `N - 1` is released.
* Day 7: Relapse `N` release candidate 1 is released.
* Days 7 - 13: Relapse `N` release candidates 2+ are released, if bugs are found.
* Day 14: Relapse `N` is released.

Note that this schedule might be modified depending on the availability of the
Relapse team, e.g. releases may be skipped to avoid holidays.

Release announcements can be found in the
[release category of the Matrix blog](https://matrix.org/category/releases).

## Bugfix releases

If a bug is found after release that is deemed severe enough (by a combination
of the impacted users and the impact on those users) then a bugfix release may
be issued. This may be at any point in the release cycle.

## Security releases

Security will sometimes be backported to the previous version and released
immediately before the next release candidate. An example of this might be:

* Day 0: Relapse N - 1 is released.
* Day 7: Relapse (N - 1).1 is released as Relapse N - 1 + the security fix.
* Day 7: Relapse N release candidate 1 is released (including the security fix).

Depending on the impact and complexity of security fixes, multiple fixes might
be held to be released together.

In some cases, a pre-disclosure of a security release will be issued as a notice
to Relapse operators that there is an upcoming security release. These can be
found in the [security category of the Matrix blog](https://matrix.org/category/security).
