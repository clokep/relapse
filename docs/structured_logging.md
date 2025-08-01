# Structured Logging

A structured logging system can be useful when your logs are destined for a
machine to parse and process. By maintaining its machine-readable characteristics,
it enables more efficient searching and aggregations when consumed by software
such as the [ELK stack](https://opensource.com/article/18/9/open-source-log-aggregation-tools).

Relapse's structured logging system is configured via the file that Relapse's
`log_config` config option points to. The file should include a formatter which
uses the `relapse.logging.TerseJsonFormatter` class included with Relapse and a
handler which uses the above formatter.

There is also a `relapse.logging.JsonFormatter` option which does not include
a timestamp in the resulting JSON. This is useful if the log ingester adds its
own timestamp.

A structured logging configuration looks similar to the following:

```yaml
version: 1

formatters:
    structured:
        class: relapse.logging.TerseJsonFormatter

handlers:
    file:
        class: logging.handlers.TimedRotatingFileHandler
        formatter: structured
        filename: /path/to/my/logs/homeserver.log
        when: midnight
        backupCount: 3  # Does not include the current log file.
        encoding: utf8

loggers:
    relapse:
        level: INFO
        handlers: [remote]
    relapse.storage.SQL:
        level: WARNING
```

The above logging config will set Relapse as 'INFO' logging level by default,
with the SQL layer at 'WARNING', and will log to a file, stored as JSON.
