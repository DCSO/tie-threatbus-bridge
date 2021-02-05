# TIE<->ThreatBus Bridge

This tool acts as a bridge between the TIE and
[Threat Bus](https://github.com/tenzir/threatbus) software components.
It can be used to regularly query the TIE API and publishes new IOCs to
ThreatBus. This is necessary since TIE does not have a push hook to use
for that purpose.

## Building

```
$ go get github.com/DCSO/tie-threatbus-bridge
```

## Running
```
$ tie-threatbus-bridge -help
Usage of ./tie-threatbus-bridge:
  -config string
    	configuration file (default "config.yaml")
  -verbose
    	be verbose

```

Example:

```
$ tie-threatbus-bridge --config config.yaml
```

## Configuration

```yaml
# Collectors settings
# -------------------
collectors:
  tie:
    # Set to true to enable this collector
    enable: true
    # TIE API version. Currently: 1
    api-version: 1
    # Base URL for the DCSO TIE service
    baseurl: https://tie.dcso.de/api/v1/iocs
    # TIE token for the API
    token: <redacted>
    # Categories to select IoCs for
    categories:
      - c2-server
      - espionage
    # Indicator types to be selected from the TIE
    data-types:
      - DomainName
      - URLVerbatim
    # Time selection constraint
    since: 4h
    # Query name, e.g. "updated_at_since", "created_at_since", "first_seen_since"
    time-query-name: created_at_since
    # Severity range to search for. Both ends need to be specified
    # (range 0-6)
    severity:
      from: 1
      to: 5
    chunk-size: 100

# Threat Bus ZeroMQ connection settings
# -------------------------------------
threatbus:
  host: 1.0.0.1
  port: 13372
```

## Operation

Trigger an update by sending `SIGUSR1` to the process:

```
$ kill -USR1 `pgrep tie-threatbus`
```
This is useful, for example, to trigger regular updates via a cron job.

## Ideas for improvement

 - Deduplication of repeating IOCs

## Contact

Sascha Steinbiss
