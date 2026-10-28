# Copilot instructions for kargo-analysisrun-logs

## Project shape

This repository is a Go service that watches Argo Rollouts `AnalysisRun` resources across Kubernetes clusters, collects per-container log streams, and exposes them through an HTTP API.

- `server.go` is the entrypoint. It creates the structured logger, initializes the local log store, starts the cluster collector, and boots the Echo router.
- `internal/collector/` owns the cluster-watching logic. It reads Kubernetes secrets from a configured namespace, filters secrets with the `argocd.postfinance.ch/secret-type=cluster` annotation, builds per-cluster REST configs, and starts informer-based watchers for remote `AnalysisRun` objects.
- `internal/store/` defines the log storage abstraction and the local disk implementation. Logs are stored under `/tmp/logs/<namespace>/<analysisRun>/<jobName>/<container>/container.log` and sanitized before use.
- `internal/router/` and `internal/handler/` provide the HTTP API. The main route is `GET /api/v1/logs/:project/:analysisRun/:jobName/:container?namespace=...` and the health check is `GET /health`.
- `internal/logger/` wraps `slog` with request-scoped context. Prefer that logger over package-level globals.

## Build, test, lint

Run from repository root:

```bash
go test ./...
```

Single-package or single-test commands:

```bash
go test -count=1 ./internal/collector

go test -count=1 -run '^TestBuildRestConfig_DefaultsExecInteractiveModeToNever$' ./internal/collector
```

For linting, this repo has a strict golangci-lint config in `.golangci.yaml`:

```bash
golangci-lint run ./...
```

Entry-point execution:

```bash
go run .
```

The repository also includes a `Taskfile.yaml` with task aliases such as `task test` and `task test-func`; use those only when the Task toolchain is installed in the environment.

## Key repo conventions

- Keep log paths and user input validated. This codebase explicitly rejects unsafe path segments and traversal attempts (`..`, separators, reserved characters) before reading or writing log files.
- Treat Kubernetes cluster secrets as runtime configuration. The collector watches the namespace configured at startup and only creates watchers for secrets marked as cluster secrets.
- Prefer context-aware logging via `logger.Get(ctx)` and `logger.Error(err)` instead of `log` or a package-global logger.
- Tests are small and side-effect-light; many unit tests use `t.Parallel()` and temporary directories, especially around collector config and local storage behavior.
- Do not rely on package-level mutable state for config or runtime tracking; the collector maintains watchers in structured maps keyed by `namespace/name` and manages lifecycle via `context.CancelFunc`.
- If you add new validation logic, keep it comparable to the existing path sanitization in `internal/store/local.go` and `internal/handler/logs.go`.

## Files to check first

When changing behavior, read these first:

- `server.go` for startup wiring
- `internal/collector/analysisrun.go` for cluster and AnalysisRun watcher behavior
- `internal/store/local.go` for log-path safety and storage rules
- `internal/handler/logs.go` for API validation and file access behavior
- `.golangci.yaml` for enforced quality gates and linter expectations

## Safety and data handling

- Remote cluster credentials are loaded from Kubernetes secrets and are not hardcoded.
- Log storage is intentionally local (`/tmp/logs`) and retention is defined in `LocalDisk` with a 72h default.
- Input sanitization is part of the contract: any new route or storage path logic should preserve the same `containsInvalidChars` and path escape checks.
