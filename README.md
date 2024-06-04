# [Gardner Falco Event Ingestor](https://gardener.cloud)

This deployment provides an Ingestor for Falco events emitted by the [Gardner Extension for Falco](https://github.com/gardener/gardener-extension-shoot-falco-service). The Ingestor verifies Sources and Events and fowards them to a dedicated Postgres database.

[![reuse compliant](https://reuse.software/badge/reuse-compliant.svg)](https://reuse.software/)

## Usage

Users may configure configure the [`values.yaml`](https://github.com/gardener/falco-event-ingestor/blob/main/chart/values.yaml) according to their needs. Users are especially required to configure the `postgres` parameters according to their cluster configuration and naming conventions.
