"""Check owned source by language; NUL-delimited Git paths preserve unusual names."""

import argparse
import json
import os
import subprocess
import tomllib
from pathlib import Path

from tooling import ROOT, cli


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", action="store_true")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    paths = args.paths or subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    ).decode().split("\0")
    groups = {name: [] for name in ("shell", "yaml", "workflow", "sql", "docker")}
    for name in paths:
        path = Path(name)
        if (
            not name
            or not path.is_file()
            or path.parts[0]
            in (
                "apps",
                "node_modules",
                ".local",
                ".superpowers",
                "secrets",
                "state",
            )
        ):
            continue
        try:
            if path.suffix == ".toml":
                tomllib.loads(path.read_text())
            elif path.suffix == ".json":
                json.loads(path.read_text())
        except (ValueError, UnicodeError) as error:
            raise ValueError(f"Invalid {path.suffix} syntax: {path}") from error
        if path.suffix == ".sh":
            groups["shell"].append(name)
        if path.suffix in (".yaml", ".yml") or path.name in (".yamllint.yml", ".ansible-lint"):
            groups["yaml"].append(name)
            if path.parts[:2] == (".github", "workflows"):
                groups["workflow"].append(name)
        if path.suffix == ".sql":
            groups["sql"].append(name)
        if path.name == "Dockerfile" or path.name.endswith(".Dockerfile"):
            groups["docker"].append(name)
    commands = [
        (
            [
                "go",
                "run",
                os.getenv("SHFMT_PACKAGE", "mvdan.cc/sh/v3/cmd/shfmt@v3.14.1"),
                "-ln",
                "posix",
                "-i",
                "4",
                "-w" if args.format else "-d",
            ],
            "shell",
        ),
        (["sqlfluff", "fix" if args.format else "lint", "--disable-progress-bar"], "sql"),
    ]
    if not args.format:
        commands.extend(
            [
                (["shellcheck", "--shell=sh"], "shell"),
                (["yamllint", "-c", str(ROOT / ".yamllint.yml")], "yaml"),
                (
                    [
                        "go",
                        "run",
                        os.getenv(
                            "ACTIONLINT_PACKAGE",
                            "github.com/rhysd/actionlint/cmd/actionlint@v1.7.12",
                        ),
                    ],
                    "workflow",
                ),
                (["hadolint"], "docker"),
            ]
        )
    for command, group in commands:
        if groups[group]:
            result = subprocess.run([*command, *sorted(set(groups[group]))], check=False)
            if result.returncode:
                return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(cli(main))
