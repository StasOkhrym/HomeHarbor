.PHONY: doctor test race vet lint lint-fix build check verify dev-init dev-up dev-down dev-trust-ca vm-up vm-down integration relay-acceptance acceptance

COMPOSE := docker compose -f deploy/compose.yaml

doctor:
	./scripts/doctor.sh

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run --fix=false

lint-fix:
	golangci-lint run --fix

build:
	go build ./cmd/...

check: test vet lint build

verify: lint
	./scripts/verify.sh

dev-init:
	./scripts/dev-init.sh

dev-up: doctor dev-init
	CONTROL_DOMAIN=$${CONTROL_DOMAIN:-control.localhost} RELAY_DOMAIN=$${RELAY_DOMAIN:-relay.localhost} CONTROL_CONFIG=../.local/control.toml RELAY_CONFIG=../.local/relay.toml $(COMPOSE) up --build -d

dev-down:
	$(COMPOSE) down

dev-trust-ca:
	./scripts/dev-trust-ca.sh

vm-up:
	./scripts/vm-up.sh

vm-down:
	./scripts/vm-down.sh

integration:
	./scripts/integration.sh

relay-acceptance:
	go test ./internal/node -run '^TestRelayOnlyNodeBridgesForwardOpaqueUDPInBothDirections$$' -count=1 -v

acceptance:
	./scripts/acceptance.sh
