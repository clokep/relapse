This directory contains some sample monitoring config for using the
'Prometheus' monitoring server against relapse.

To use it, first install prometheus by following the instructions at

  http://prometheus.io/

### for Prometheus v1

Add a new job to the main prometheus.conf file:

```yaml
  job: {
    name: "relapse"

    target_group: {
      target: "http://SERVER.LOCATION.HERE:PORT/_relapse/metrics"
    }
  }
```

### for Prometheus v2

Add a new job to the main prometheus.yml file:

```yaml
  - job_name: "relapse"
    metrics_path: "/_relapse/metrics"
    # when endpoint uses https:
    scheme: "https"

    static_configs:
    - targets: ["my.server.here:port"]
```

An example of a Prometheus configuration with workers can be found in
[metrics-howto.md](https://clokep.github.io/relapse/latest/metrics-howto.html).

To use `relapse.rules` add

```yaml
  rule_files:
    - "/PATH/TO/relapse-v2.rules"
```

Metrics are disabled by default when running relapse; they must be enabled
with the 'enable-metrics' option, either in the relapse config file or as a
command-line option.
