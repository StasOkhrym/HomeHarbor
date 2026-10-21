"""Verify account HTTP flows with owned PostgreSQL, Redis and TLS SMTP capture."""

import json
import tempfile

import integration
import integration_mail
from process_owner import run
from tooling import cli

CONTRACT = integration.COMPOSED_ACCOUNT_CONTRACT
PACKAGE = "github.com/StasOkhrym/homeharbor/internal/app/control"


def contracts(env):
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        result = run(
            [
                "go",
                "test",
                "-race",
                "-json",
                "./internal/app/control",
                "-run",
                "^" + CONTRACT + "$",
                "-count=1",
                "-timeout=120s",
            ],
            {**env, "TEST_ACCOUNT_JOURNEY": "1"},
            stdout=output,
        )
        output.seek(0)
        passed = False
        skipped = False
        for line in output:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                if result:
                    continue

                raise ValueError("Account contract produced invalid test events") from None

            if event.get("Output"):
                print(event["Output"], end="", flush=True)

            skipped |= event.get("Action") == "skip"
            if event.get("Package") == PACKAGE and event.get("Test") == CONTRACT:
                passed |= event.get("Action") == "pass"

        if result:
            return result
        if skipped or not passed:
            raise ValueError("Required account journey was missing or skipped")

    print("Composed account HTTP/SQL/Redis/Mailpit journey passed without skips")
    return 0


def with_mail(env):
    return integration_mail.main(contracts, env)


def main():
    return integration.main(with_mail)


if __name__ == "__main__":
    raise SystemExit(cli(main))
