# Relapse Docker

This Docker image will run Relapse as a single process. By default it uses a
sqlite database; for production use you should connect it to a separate
postgres database. The image also does *not* provide a TURN server.

This image should work on all platforms that are supported by Docker upstream.
Note that Docker's WS1-backend Linux Containers on Windows
platform is [experimental](https://github.com/docker/for-win/issues/6470) and
is not supported by this image.

## Volumes

By default, the image expects a single volume, located at `/data`, that will hold:

* configuration files;
* uploaded media and thumbnails;
* the SQLite database if you do not configure postgres;
* the appservices configuration.

You are free to use separate volumes depending on storage endpoints at your
disposal. For instance, `/data/media` could be stored on a large but low
performance hdd storage while other files could be stored on high performance
endpoints.

In order to setup an application service, simply create an `appservices`
directory in the data volume and write the application service Yaml
configuration file there. Multiple application services are supported.

## Generating a configuration file

The first step is to generate a valid config file. To do this, you can run the
image with the `generate` command line option.

You will need to specify values for the `RELAPSE_SERVER_NAME` and
`RELAPSE_REPORT_STATS` environment variable, and mount a docker volume to store
the configuration on. For example:

```
docker run -it --rm \
    --mount type=volume,src=relapse-data,dst=/data \
    -e RELAPSE_SERVER_NAME=my.matrix.host \
    -e RELAPSE_REPORT_STATS=yes \
    clokep/relapse:latest generate
```

For information on picking a suitable server name, see
https://clokep.github.io/relapse/latest/setup/installation.html.

The above command will generate a `homeserver.yaml` in (typically)
`/var/lib/docker/volumes/relapse-data/_data`. You should check this file, and
customise it to your needs.

The following environment variables are supported in `generate` mode:

* `RELAPSE_SERVER_NAME` (mandatory): the server public hostname.
* `RELAPSE_REPORT_STATS` (mandatory, `yes` or `no`): whether to enable
  anonymous statistics reporting.
* `RELAPSE_HTTP_PORT`: the port Relapse should listen on for http traffic.
      Defaults to `8008`.
* `RELAPSE_CONFIG_DIR`: where additional config files (such as the log config
  and event signing key) will be stored. Defaults to `/data`.
* `RELAPSE_CONFIG_PATH`: path to the file to be generated. Defaults to
  `<RELAPSE_CONFIG_DIR>/homeserver.yaml`.
* `RELAPSE_DATA_DIR`: where the generated config will put persistent data
  such as the database and media store. Defaults to `/data`.
* `UID`, `GID`: the user id and group id to use for creating the data
  directories. If unset, and no user is set via `docker run --user`, defaults
  to `991`, `991`.
* `RELAPSE_LOG_LEVEL`: the log level to use (one of `DEBUG`, `INFO`, `WARNING` or `ERROR`).
  Defaults to `INFO`.
* `RELAPSE_LOG_SENSITIVE`: if set and the log level is set to `DEBUG`, Relapse
  will log sensitive information such as access tokens.
  This should not be needed unless you are a developer attempting to debug something
  particularly tricky.
* `RELAPSE_LOG_TESTING`: if set, Relapse will log additional information useful
  for testing.

## Postgres

By default the config will use SQLite. See the [docs on using Postgres](https://github.com/clokep/relapse/blob/develop/docs/postgres.md) for more info on how to use Postgres. Until this section is improved [this issue](https://github.com/clokep/relapse/issues/8304) may provide useful information.

## Running relapse

Once you have a valid configuration file, you can start relapse as follows:

```
docker run -d --name relapse \
    --mount type=volume,src=relapse-data,dst=/data \
    -p 8008:8008 \
    clokep/relapse:latest
```

(assuming 8008 is the port Relapse is configured to listen on for http traffic.)

You can then check that it has started correctly with:

```
docker logs relapse
```

If all is well, you should now be able to connect to http://localhost:8008 and
see a confirmation message.

The following environment variables are supported in `run` mode:

* `RELAPSE_CONFIG_DIR`: where additional config files are stored. Defaults to
  `/data`.
* `RELAPSE_CONFIG_PATH`: path to the config file. Defaults to
  `<RELAPSE_CONFIG_DIR>/homeserver.yaml`.
* `RELAPSE_WORKER`: module to execute, used when running relapse with workers.
   Defaults to `relapse.app.homeserver`, which is suitable for non-worker mode.
* `UID`, `GID`: the user and group id to run Relapse as. If unset, and no user
  is set via `docker run --user`, defaults to `991`, `991`. Note that this user
  must have permission to read the config files, and write to the data directories.
* `TZ`: the [timezone](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) the container will run with. Defaults to `UTC`.

For more complex setups (e.g. for workers) you can also pass your args directly to relapse using `run` mode. For example like this:

```
docker run -d --name relapse \
    --mount type=volume,src=relapse-data,dst=/data \
    -p 8008:8008 \
    clokep/relapse:latest run \
    -m relapse.app.generic_worker \
    --config-path=/data/homeserver.yaml \
    --config-path=/data/generic_worker.yaml
```

If you do not provide `-m`, the value of the `RELAPSE_WORKER` environment variable is used. If you do not provide at least one `--config-path` or `-c`, the value of the `RELAPSE_CONFIG_PATH` environment variable is used instead.

## Generating an (admin) user

After relapse is running, you may wish to create a user via `register_new_matrix_user`.

This requires a `registration_shared_secret` to be set in your config file. Relapse
must be restarted to pick up this change.

You can then call the script:

```
docker exec -it relapse register_new_matrix_user http://localhost:8008 -c /data/homeserver.yaml --help
```

Remember to remove the `registration_shared_secret` and restart if you no-longer need it.

## TLS support

The default configuration exposes a single HTTP port: http://localhost:8008. It
is suitable for local testing, but for any practical use, you will either need
to use a reverse proxy, or configure Relapse to expose an HTTPS port.

For documentation on using a reverse proxy, see
https://github.com/clokep/relapse/blob/master/docs/reverse_proxy.md.

For more information on enabling TLS support in relapse itself, see
https://clokep.github.io/relapse/latest/setup/installation.html#tls-certificates. Of
course, you will need to expose the TLS port from the container with a `-p`
argument to `docker run`.

## Legacy dynamic configuration file support

The docker image used to support creating a dynamic configuration file based
on environment variables. This is no longer supported, and an error will be
raised if you try to run relapse without a config file.

It is, however, possible to generate a static configuration file based on
the environment variables that were previously used. To do this, run the docker
container once with the environment variables set, and `migrate_config`
command line option. For example:

```
docker run -it --rm \
    --mount type=volume,src=relapse-data,dst=/data \
    -e RELAPSE_SERVER_NAME=my.matrix.host \
    -e RELAPSE_REPORT_STATS=yes \
    clokep/relapse:latest migrate_config
```

This will generate the same configuration file as the legacy mode used, and
will store it in `/data/homeserver.yaml`. You can then use it as shown above at
[Running relapse](#running-relapse).

Note that the defaults used in this configuration file may be different to
those when generating a new config file with `generate`: for example, TLS is
enabled by default in this mode. You are encouraged to inspect the generated
configuration file and edit it to ensure it meets your needs.

## Building the image

If you need to build the image from a Relapse checkout, use the following `docker
 build` command from the repo's root:

```
DOCKER_BUILDKIT=1 docker build -t clokep/relapse -f docker/Dockerfile .
```

You can choose to build a different docker image by changing the value of the `-f` flag to
point to another Dockerfile.

## Disabling the healthcheck

If you are using a non-standard port or tls inside docker you can disable the healthcheck
whilst running the above `docker run` commands.

```
   --no-healthcheck
```

## Disabling the healthcheck in docker-compose file

If you wish to disable the healthcheck via docker-compose, append the following to your service configuration.

```
  healthcheck:
    disable: true
```

## Setting custom healthcheck on docker run

If you wish to point the healthcheck at a different port with docker command, add the following

```
  --health-cmd 'curl -fSs http://localhost:1234/health'
```

## Setting the healthcheck in docker-compose file

You can add the following to set a custom healthcheck in a docker compose file.
You will need docker-compose version >2.1 for this to work.

```
healthcheck:
  test: ["CMD", "curl", "-fSs", "http://localhost:8008/health"]
  interval: 15s
  timeout: 5s
  retries: 3
  start_period: 5s
```

## Using jemalloc

Jemalloc is embedded in the image and will be used instead of the default allocator.
You can read about jemalloc by reading the Relapse
[Admin FAQ](https://clokep.github.io/relapse/latest/usage/administration/admin_faq.html#help-relapse-is-slow-and-eats-all-my-ramcpu).
