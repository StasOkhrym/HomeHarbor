.DEFAULT_GOAL := help
ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
MAKEFLAGS += --no-print-directory
export PYTHONDONTWRITEBYTECODE := 1
export PATH := $(ROOT).local/ui-tooling/bin:$(PATH)
PYTHON ?= python3
FULL ?= 0
export GO_PACKAGES := ./cmd/... ./internal/... ./migrations/...
export SHFMT_PACKAGE := mvdan.cc/sh/v3/cmd/shfmt@v3.14.1
export ACTIONLINT_PACKAGE := github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
ACTION ?= run
CHECK ?= allowed
FUZZ_TIME ?= 5s
SECURITY ?= all

.PHONY: help doctor fmt lint test verify security integration acceptance dev-up dev-down dev-logs dev-trust-ca

help:
	@printf '%s\n' \
	  'doctor: report missing local dependencies (PROFILE=backend|compose|e2e|sandbox)' \
	  'fmt / lint / test / verify: format, read-only checks, tests, portable gate' \
	  'verify FULL=1: additionally integration, security, local Compose and Linux acceptance' \
	  'security / integration / acceptance: explicit heavier gates' \
	  'dev-up / dev-down / dev-logs / dev-trust-ca: local UI stack and test CA' \
	  'sandbox-up/client/gateway/prepare/status/logs/check/down/reset: optional manual Mac flow'

doctor:
	cd "$(ROOT)" && sh scripts/doctor.sh $(or $(PROFILE),backend)

fmt:
	cd "$(ROOT)" && golangci-lint fmt $(GO_PACKAGES)
	cd "$(ROOT)" && ruff check --fix scripts && ruff format scripts
	cd "$(ROOT)" && npm run format && djlint internal/web/assets/templates --reformat
	cd "$(ROOT)" && $(PYTHON) scripts/lint_files.py --format

lint:
	cd "$(ROOT)" && sh scripts/format-check.sh
	cd "$(ROOT)" && golangci-lint run --fix=false $(GO_PACKAGES)
	cd "$(ROOT)" && ruff check --no-cache scripts
	cd "$(ROOT)" && npm run lint && djlint internal/web/assets/templates --lint
	cd "$(ROOT)" && $(PYTHON) scripts/lint_files.py

test:
	cd "$(ROOT)" && go test $(GO_PACKAGES) -count=1
	cd "$(ROOT)" && $(PYTHON) -m unittest discover -s scripts/tests
	cd "$(ROOT)" && node --test internal/web/assets/tests/browser.test.cjs

verify:
	cd "$(ROOT)" && FULL=$(FULL) sh scripts/verify.sh

security:
	@case '$(SECURITY)' in all|fuzz|vulnerability) ;; *) echo 'Invalid SECURITY gate' >&2; exit 2;; esac
ifneq ($(SECURITY),vulnerability)
	cd "$(ROOT)" && go test ./internal/protocol -run '^$$' -fuzz '^FuzzCandidateUpdateJSON$$' -fuzztime=$(FUZZ_TIME)
	cd "$(ROOT)" && go test ./internal/relay -run '^$$' -fuzz '^FuzzRelayTicketVerify$$' -fuzztime=$(FUZZ_TIME)
	cd "$(ROOT)" && go test ./internal/snapshot -run '^$$' -fuzz '^FuzzDecodeSnapshot$$' -fuzztime=$(FUZZ_TIME)
endif
ifneq ($(SECURITY),fuzz)
	cd "$(ROOT)" && go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 $(GO_PACKAGES)
endif

integration:
	cd "$(ROOT)" && $(PYTHON) scripts/integration.py

acceptance:
	cd "$(ROOT)" && sh scripts/acceptance.sh

dev-up dev-down dev-logs:
	cd "$(ROOT)" && sh scripts/dev.sh $(patsubst dev-%,%,$@)

dev-trust-ca:
	cd "$(ROOT)" && sh scripts/dev-trust-ca.sh

.PHONY: sandbox-up sandbox-client sandbox-gateway sandbox-prepare sandbox-status sandbox-logs sandbox-check sandbox-down sandbox-reset

sandbox-up sandbox-status sandbox-logs sandbox-down sandbox-reset:
	cd "$(ROOT)" && PYTHON="$(PYTHON)" sh scripts/sandbox.sh $(patsubst sandbox-%,%,$@)

sandbox-client sandbox-gateway:
	@case "$(ACTION)" in run|join|close|enroll) ;; *) echo "Invalid sandbox ACTION" >&2; exit 2;; esac
	cd "$(ROOT)" && PYTHON="$(PYTHON)" sh scripts/sandbox.sh $(patsubst sandbox-%,%,$@) "$(ACTION)"

sandbox-prepare:
	cd "$(ROOT)" && PYTHON="$(PYTHON)" sh scripts/sandbox.sh prepare

sandbox-check:
	@case "$(CHECK)" in allowed|denied) ;; *) echo "Invalid sandbox CHECK" >&2; exit 2;; esac
	cd "$(ROOT)" && PYTHON="$(PYTHON)" sh scripts/sandbox.sh check "$(CHECK)"
