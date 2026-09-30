.PHONY: doctor test race fuzz vet lint lint-fix vulncheck build check verify compose-check dev-init dev-up dev-down dev-trust-ca vm-up vm-down integration relay-acceptance acceptance

COMPOSE := docker compose -f deploy/compose.yaml

doctor:
	./scripts/doctor.sh

test:
	go test ./...

race:
	go test -race ./...

fuzz:
	go test ./internal/protocol -run=^$$ -fuzz=Fuzz -fuzztime=5s
	go test ./internal/relay -run=^$$ -fuzz=FuzzDecodePacket -fuzztime=5s
	go test ./internal/relay -run=^$$ -fuzz=FuzzDecodeUDPPairDatagram -fuzztime=5s
	go test ./internal/snapshot -run=^$$ -fuzz=Fuzz -fuzztime=5s

vet:
	go vet ./...

lint:
	golangci-lint run --fix=false

lint-fix:
	golangci-lint run --fix

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

build:
	go build ./cmd/...

check: test vet lint build

verify: lint
	./scripts/verify.sh

dev-init:
	./scripts/dev-init.sh

dev-up: doctor dev-init compose-check
	CONTROL_DOMAIN=$${CONTROL_DOMAIN:-control.localhost} RELAY_DOMAIN=$${RELAY_DOMAIN:-relay.localhost} CADDYFILE=Caddyfile.local CONTROL_CONFIG=../.local/control.toml RELAY_CONFIG=../.local/relay.toml $(COMPOSE) up --build -d --wait --wait-timeout 120

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

compose-check:
	./scripts/compose-check.sh

relay-acceptance:
	go test ./internal/node -run '^TestRelayOnlyNodeBridgesForwardOpaqueUDPInBothDirections$$' -count=1 -v

acceptance:
	./scripts/acceptance.sh
