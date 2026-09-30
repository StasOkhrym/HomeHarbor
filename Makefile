.PHONY: doctor doctor-compose test race fuzz vet lint lint-fix vulncheck build android-build ios-source-check check verify compose-check deploy-check dev-init dev-up dev-down dev-trust-ca vm-up vm-down integration integration-local relay-acceptance acceptance

COMPOSE := docker compose -f deploy/compose.yaml

doctor:
	./scripts/doctor.sh

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

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

build:
	go build ./cmd/...

android-build:
	gradle -p apps/android assembleDebug

ios-source-check:
	xcodebuild -packagePath apps/ios -scheme GoTunnelsIOS-Package -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build

check: test vet lint build

verify: lint
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
