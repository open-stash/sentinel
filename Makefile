# Sentinel owns auth_db. Its DB URL and goose table are baked in here so the
# connection string is never hand-typed (hand-typing once pointed kyber's
# migrations at auth_db). Override on the CLI for prod, e.g.:
#   make migrate-up DB_URL="postgres://...aiven.../auth_db?sslmode=require"
# Override GOOSE if `goose` isn't on PATH:
#   make migrate-up GOOSE="$(go env GOPATH)/bin/goose"
GOOSE       ?= goose
GOOSE_TABLE ?= goose_db_version
DB_URL      ?= postgres://auth_user:secret@localhost:5432/auth_db?sslmode=disable

build:
	go build -o ./bin/sentinel ./cmd/main.go

run:
	go run ./cmd/main.go

migrate-up:
	GOOSE_TABLE=$(GOOSE_TABLE) $(GOOSE) -dir migrations postgres "$(DB_URL)" up

migrate-down:
	GOOSE_TABLE=$(GOOSE_TABLE) $(GOOSE) -dir migrations postgres "$(DB_URL)" down

migrate-status:
	GOOSE_TABLE=$(GOOSE_TABLE) $(GOOSE) -dir migrations postgres "$(DB_URL)" status

migrate-create:
	$(GOOSE) -dir migrations create $(NAME) sql

sqlc:
	cd sqlc && sqlc generate
