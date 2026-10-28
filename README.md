# kargo-analysisrun-logs

A Go service that watches Argo Rollouts `AnalysisRun` resources across Kubernetes clusters, captures the log output of job-backed metric containers, and exposes those logs through a small HTTP API.

## What it does

At startup the app creates a structured logger, initializes a local log store under `/tmp/logs`, starts a collector that watches cluster secrets in a configured namespace, and boots an Echo API server.

The collector:

- reads Kubernetes secrets annotated as cluster credentials
- builds per-cluster REST configs
- watches `AnalysisRun` resources via the Argo Rollouts informer
- starts log-stream collection for job-based metric containers
- writes log files to the local filesystem for later retrieval

The HTTP layer exposes log files via:

- `GET /health`
- `GET /api/v1/logs/:project/:analysisRun/:jobName/:container?namespace=...`

## Architecture

- `server.go` — application entrypoint and wiring
- `internal/collector/` — cluster secret discovery, remote client config, informer lifecycle, and log-stream collection
- `internal/store/` — storage interface and local disk implementation
- `internal/handler/` — HTTP handlers and path validation
- `internal/router/` — Echo route registration
- `internal/logger/` — context-aware slog setup

## Prerequisites

- Go 1.26.5 (see `go.mod`)
- Access to a Kubernetes cluster with the relevant RBAC permissions
- A namespace containing cluster secrets used by the collector
- Optional: `golangci-lint` for linting

## Configuration

The application reads:

- `LOG_LEVEL` — log verbosity (`debug`, `info`, `warn`, `error`)
- `KARGO_NAMESPACE` — namespace containing cluster secrets; defaults to `kube-kargo`

Example:

```bash
export LOG_LEVEL=info
export KARGO_NAMESPACE=kube-kargo
go run .
```

## Build and test

Run the full Go test suite:

```bash
go test ./...
```

Run a package or single test:

```bash
go test -count=1 ./internal/collector

go test -count=1 -run '^TestBuildRestConfig_DefaultsExecInteractiveModeToNever$' ./internal/collector
```

Run the app directly:

```bash
go run .
```

Lint:

```bash
golangci-lint run ./...
```

This repo also includes a `Taskfile.yaml` with helper tasks such as `task test` and `task test-func` when the Task toolchain is installed.

## Log storage and safety

Local log files are stored under `/tmp/logs` with a path shaped like:

```text
/tmp/logs/<namespace>/<analysisRun>/<jobName>/<container>/container.log
```

The code validates path parts and blocks traversal attempts and unsafe characters before reading or writing files. This is enforced both in the storage layer and in the HTTP handler.

## Notes

- Remote cluster credentials are loaded from Kubernetes secrets rather than hardcoded values.
- The local storage implementation retains logs for 72 hours by default.
- The collector only starts watchers for secrets that match the cluster-secret marker annotation used by this project.
