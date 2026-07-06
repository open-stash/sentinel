# syntax=docker/dockerfile:1

# --- build stage -------------------------------------------------------------
# Pinned to the go.mod toolchain. CGO is off so the result is a fully static
# binary that runs on the distroless/static base below.
FROM golang:1.25.4-bookworm AS build

WORKDIR /src

# Cache modules separately from source so dependency layers stay warm.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# Trim the binary and stamp the version (passed by CI via --build-arg).
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/sentinel ./cmd/main.go

# --- runtime stage -----------------------------------------------------------
# distroless/static: no shell, no package manager, ships ca-certificates and a
# non-root user (uid 65532). Nothing to attack, tiny image.
FROM gcr.io/distroless/static:nonroot

WORKDIR /app

# Config and keys are gitignored / secret and are NOT baked in. Mount them at
# runtime, e.g.:
#   docker run -p 8080:8080 \
#     -v $PWD/internal/config/config.yaml:/app/internal/config/config.yaml:ro \
#     -v $PWD/keys:/app/keys:ro \
#     ghcr.io/open-stash/sentinel:latest
# Viper also reads env overrides (server.port -> SERVER_PORT, database.dsn ->
# DATABASE_DSN, ...), so most values can come from the environment instead.
COPY --from=build /out/sentinel /app/sentinel

EXPOSE 8080

USER nonroot:nonroot
ENTRYPOINT ["/app/sentinel"]
