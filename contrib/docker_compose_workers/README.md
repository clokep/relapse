# Setting up Relapse with Workers using Docker Compose

This directory describes how deploy and manage Relapse and workers via [Docker Compose](https://docs.docker.com/compose/).

Example worker configuration files can be found [here](workers).

All examples and snippets assume that your Relapse service is called `relapse` in your Docker Compose file.

An example Docker Compose file can be found [here](docker-compose.yaml).

## Worker Service Examples in Docker Compose

In order to start the Relapse container as a worker, you must specify an `entrypoint` that loads both the `homeserver.yaml` and the configuration for the worker (`relapse-generic-worker-1.yaml` in the example below). You must also include the worker type in the environment variable `RELAPSE_WORKER` or alternatively pass `-m relapse.app.generic_worker` as part of the `entrypoint` after `"/start.py", "run"`).

### Generic Worker Example

```yaml
relapse-generic-worker-1:
  image: matrixdotorg/relapse:latest
  container_name: relapse-generic-worker-1
  restart: unless-stopped
  entrypoint: ["/start.py", "run", "--config-path=/data/homeserver.yaml", "--config-path=/data/workers/relapse-generic-worker-1.yaml"]
  healthcheck:
    test: ["CMD-SHELL", "curl -fSs http://localhost:8081/health || exit 1"]
    start_period: "5s"
    interval: "15s"
    timeout: "5s"
  volumes:
    - ${VOLUME_PATH}/data:/data:rw # Replace VOLUME_PATH with the path to your Relapse volume
  environment:
    RELAPSE_WORKER: relapse.app.generic_worker
  # Expose port if required so your reverse proxy can send requests to this worker
  # Port configuration will depend on how the http listener is defined in the worker configuration file
  ports:
    - 8081:8081
  depends_on:
    - relapse
```

### Federation Sender Example

Please note: The federation sender does not receive REST API calls so no exposed ports are required.

```yaml
relapse-federation-sender-1:
  image: matrixdotorg/relapse:latest
  container_name: relapse-federation-sender-1
  restart: unless-stopped
  entrypoint: ["/start.py", "run", "--config-path=/data/homeserver.yaml", "--config-path=/data/workers/relapse-federation-sender-1.yaml"]
  healthcheck:
    disable: true
  volumes:
    - ${VOLUME_PATH}/data:/data:rw # Replace VOLUME_PATH with the path to your Relapse volume
  environment:
    RELAPSE_WORKER: relapse.app.generic_worker
  depends_on:
    - relapse
```

## `homeserver.yaml` Configuration

### Enable Redis

Locate the `redis` section of your `homeserver.yaml` and enable and configure it:

```yaml
redis:
  enabled: true
  host: redis
  port: 6379
  # dbid:  <redis_logical_db_id>
  # password: <secret_password>  
  # use_tls: True
  # certificate_file: <path_to_certificate>
  # private_key_file: <path_to_private_key>
  # ca_file: <path_to_ca_certificate>
```

This assumes that your Redis service is called `redis` in your Docker Compose file.

### Add a replication Listener

Locate the `listeners` section of your `homeserver.yaml` and add the following replication listener:

```yaml
listeners:
  # Other listeners

  - port: 9093
    type: http
    resources:
      - names: [replication]
```

This listener is used by the workers for replication and is referred to in worker config files using the following settings:

```yaml
worker_replication_host: relapse
worker_replication_http_port: 9093
```

### Configure Federation Senders

This section is applicable if you are using Federation senders. Locate the `federation_sender_instances` settings in your `homeserver.yaml` and configure them:

```yaml
# This will disable federation sending on the main Relapse instance
federation_sender_instances:
  - relapse-federation-sender-1 # The worker_name setting in your federation sender worker configuration file
```

## Other Worker types

Using the concepts shown here it is possible to create other worker types in Docker Compose. See the [Workers](https://clokep.github.io/relapse/latest/workers.html#available-worker-applications) documentation for a list of available workers.
