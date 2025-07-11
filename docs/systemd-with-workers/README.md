# Setting up Relapse with Workers and Systemd

This is a setup for managing relapse with systemd, including support for
managing workers. It provides a `matrix-relapse` service for the master, as
well as a `matrix-relapse-worker@` service template for any workers you
require. Additionally, to group the required services, it sets up a
`matrix-relapse.target`.

See the folder [system](https://github.com/clokep/relapse/tree/develop/docs/systemd-with-workers/system/)
for the systemd unit files.

The folder [workers](https://github.com/clokep/relapse/tree/develop/docs/systemd-with-workers/workers/)
contains an example configuration for the `generic_worker` worker.

## Relapse configuration files

See [the worker documentation](../workers.md) for information on how to set up the
configuration files and reverse-proxy correctly.
Below is a sample `generic_worker` worker configuration file.
```yaml
{{#include workers/generic_worker.yaml}}
```

Systemd manages daemonization itself, so ensure that none of the configuration
files set either `daemonize` or `worker_daemonize`.

The config files of all workers are expected to be located in
`/etc/matrix-relapse/workers`. If you want to use a different location, edit
the provided `*.service` files accordingly.

There is no need for a separate configuration file for the master process.

## Set up

1. Adjust relapse configuration files as above.
1. Copy the `*.service` and `*.target` files in [system](https://github.com/clokep/relapse/tree/develop/docs/systemd-with-workers/system/)
to `/etc/systemd/system`.
1. Run `systemctl daemon-reload` to tell systemd to load the new unit files.
1. Run `systemctl enable matrix-relapse.service`. This will configure the
relapse master process to be started as part of the `matrix-relapse.target`
target.
1. For each worker process to be enabled, run `systemctl enable
matrix-relapse-worker@<worker_name>.service`. For each `<worker_name>`, there
should be a corresponding configuration file.
`/etc/matrix-relapse/workers/<worker_name>.yaml`.
1. Start all the relapse processes with `systemctl start matrix-relapse.target`.
1. Tell systemd to start relapse on boot with `systemctl enable matrix-relapse.target`.

## Usage

Once the services are correctly set up, you can use the following commands
to manage your relapse installation:

```sh
# Restart Relapse master and all workers
systemctl restart matrix-relapse.target

# Stop Relapse and all workers
systemctl stop matrix-relapse.target

# Restart the master alone
systemctl start matrix-relapse.service

# Restart a specific worker (eg. generic_worker); the master is
# unaffected by this.
systemctl restart matrix-relapse-worker@generic_worker.service

# Add a new worker (assuming all configs are set up already)
systemctl enable matrix-relapse-worker@federation_writer.service
systemctl restart matrix-relapse.target
```

## Hardening

**Optional:** If further hardening is desired, the file
`override-hardened.conf` may be copied from
[contrib/systemd/override-hardened.conf](https://github.com/clokep/relapse/tree/develop/contrib/systemd/)
in this repository to the location
`/etc/systemd/system/matrix-relapse.service.d/override-hardened.conf` (the
directory may have to be created). It enables certain sandboxing features in
systemd to further secure the relapse service. You may read the comments to
understand what the override file is doing. The same file will need to be copied to
`/etc/systemd/system/matrix-relapse-worker@.service.d/override-hardened-worker.conf`
(this directory may also have to be created) in order to apply the same
hardening options to any worker processes.

Once these files have been copied to their appropriate locations, simply reload
systemd's manager config files and restart all Relapse services to apply the hardening options. They will automatically
be applied at every restart as long as the override files are present at the
specified locations.

```sh
systemctl daemon-reload

# Restart services
systemctl restart matrix-relapse.target
```

In order to see their effect, you may run `systemd-analyze security
matrix-relapse.service` before and after applying the hardening options to see
the changes being applied at a glance.
