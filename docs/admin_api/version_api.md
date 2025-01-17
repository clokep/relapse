# Version API

This API returns the running Relapse version.
This is useful when a Relapse instance
is behind a proxy that does not forward the 'Server' header (which also
contains Relapse version information).

The api is:

```
GET /_relapse/admin/v1/server_version
```

It returns a JSON body like the following:

```json
{
    "server_version": "0.99.2rc1 (b=develop, abcdef123)"
}
```

*Changed in Relapse 1.94.0:* The `python_version` key was removed from the
response body.
