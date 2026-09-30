.PHONY: doctor doctor-backend doctor-compose doctor-e2e doctor-ios fmt fmt-check gofumpt gci goimports scripts-test architecture e2e test race fuzz vet lint lint-fix vulncheck build android-build ios-source-check check verify compose-check deploy-check dev-init dev-up dev-down dev-trust-ca vm-up vm-down integration integration-local relay-acceptance acceptance

COMPOSE := docker compose -f deploy/compose.yaml

doctor:
	./scripts/doctor.sh backend

doctor-backend: doctor

doctor-e2e:
	./scripts/doctor.sh e2e

doctor-ios:
	./scripts/doctor.sh ios

doctor-compose:
	./scripts/doctor.sh compose

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
	golangci-lint run --fix=false ./...

lint-fix:
	golangci-lint run --fix ./...

fmt:
	golangci-lint fmt ./...

# Also inspect output: formatter versions can exit zero for dirty files.
fmt-check:
	@output=$$(mktemp); trap 'rm -f "$$output"' EXIT HUP INT TERM; \
	status=0; golangci-lint fmt --diff ./... >"$$output" || status=$$?; \
	if test -s "$$output"; then cat "$$output"; echo 'Run make fmt to format Go sources' >&2; exit 1; fi; exit $$status

# Named entrypoints use the full configured pipeline so spacing and module
# import grouping stay consistent, with no additional formatter installation.
gofumpt gci goimports: fmt

scripts-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -v

architecture:
	go test ./internal/architecture -count=1

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

build:
	go build ./cmd/...

android-build:
	gradle -p apps/android assembleDebug

ios-source-check:
	xcodebuild -packagePath apps/ios -scheme GoTunnelsIOS-Package -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build

check: fmt-check test vet lint build architecture scripts-test

verify:
	./scripts/verify.sh

dev-init:
	./scripts/dev-init.sh

dev-up: doctor-compose dev-init compose-check
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

integration-local:
	./scripts/integration-local.sh

compose-check:
	./scripts/compose-check.sh

deploy-check:
	./scripts/deploy-check.sh

relay-acceptance:
	go test ./internal/app/relay -run '^TestRelayAppBridgesTwoNodesThroughProductionListeners$$' -count=1 -v
	go test ./internal/node -run '^TestRelayOnlyNodeBridgesForwardOpaqueUDPInBothDirections$$' -count=1 -v

acceptance:
	./scripts/acceptance.sh

# The parent owns the real VM/network acceptance implementation.
e2e:
	./scripts/e2e.sh
