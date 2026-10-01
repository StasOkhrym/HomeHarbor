"""Validate the explicit Ansible bundle, rendered TOML/Compose and runtime permissions."""

import json
import os
import subprocess
import tempfile
import tomllib
from pathlib import Path

import yaml
from compose_check import render, secrets
from jinja2 import Environment, StrictUndefined
from tooling import ROOT, cli, require_commands

BUNDLE = {
    "go.mod",
    "go.sum",
    ".dockerignore",
    "cmd/",
    "internal/",
    "migrations/",
    "deploy/Dockerfile",
    "deploy/compose.yaml",
}
RUNTIME_SECRETS = {
    "postgres_password",
    "redis_password",
    "session_signing_key",
    "ceremony_encryption_key",
    "relay_ticket_key",
    "root_public_key",
    "relay_tls_ca",
    "relay_tls_cert",
    "relay_tls_key",
    "dns_provider_token",
}


def main():
    require_commands("docker", "ansible-playbook")
    playbook = ROOT / "deploy/ansible/site.yml"
    play = yaml.safe_load(playbook.read_text())[0]
    tasks = play["tasks"]
    copies = [t for t in tasks if "ansible.builtin.copy" in t]
    bundle = next(t for t in copies if "src" in t["ansible.builtin.copy"])
    if set(bundle["loop"]) != BUNDLE or bundle["ansible.builtin.copy"]["src"] != "../../{{ item }}":
        raise ValueError("Ansible must copy the explicit build bundle, excluding rendered configs")
    if any(not (ROOT / item).exists() for item in BUNDLE):
        raise ValueError("Ansible bundle source missing")
    secret_task = next(t for t in copies if "content" in t["ansible.builtin.copy"])
    if set(secret_task["loop"]) != RUNTIME_SECRETS or not secret_task.get("no_log"):
        raise ValueError("Ansible must write exactly the validated runtime secrets without logging")
    for task in [secret_task, *(t for t in tasks if "ansible.builtin.template" in t)]:
        module = task.get("ansible.builtin.copy", task.get("ansible.builtin.template"))
        if (module["owner"], str(module["group"]), module["mode"]) != ("root", "65532", "0640"):
            raise ValueError("Runtime configs/secrets must be root:65532 mode 0640")
    # A repeated run must not flip ownership of one directory between tasks.
    directories = []
    for task in tasks:
        if "ansible.builtin.file" in task:
            module = task["ansible.builtin.file"]
            directories.extend(task.get("loop", [module["path"]]))
    if len(directories) != len(set(directories)):
        raise ValueError("Ansible directory ownership would change on every run")
    jinja = Environment(undefined=StrictUndefined, autoescape=False)
    jinja.filters["to_json"] = json.dumps
    context = {
        "control_domain": "control.example.test",
        "relay_domain": "relay.example.test",
        "network_id": "test-network",
        "trusted_proxy_cidrs": ["172.16.0.0/12"],
        "acme_email": "operator@example.test",
        "dns_provider": "cloudflare",
        "dns_provider_file_environment": {
            "CF_DNS_API_TOKEN_FILE": "/run/secrets/dns_provider_token"
        },
    }
    with tempfile.TemporaryDirectory(prefix="go-tunnels-deploy-check-") as directory:
        temp = Path(directory)
        documents = {}
        for name in (
            "control.toml",
            "relay.toml",
            "traefik.toml",
            "proxy-routes.toml",
            "compose.production.yaml",
        ):
            source = ROOT / "deploy/ansible/templates" / (name + ".j2")
            rendered = jinja.from_string(source.read_text()).render(context)
            (temp / name).write_text(rendered)
            documents[name] = (
                yaml.safe_load(rendered) if name.endswith("yaml") else tomllib.loads(rendered)
            )
        control, relay = documents["control.toml"], documents["relay.toml"]
        if control["server"]["public_url"] != "https://" + context["control_domain"]:
            raise ValueError("Rendered control public URL differs from DNS routing")
        if (
            control["auth"]["rp_id"] != context["control_domain"]
            or control["auth"]["rp_origin"] != control["server"]["public_url"]
        ):
            raise ValueError("Rendered WebAuthn origin and RP ID must match control DNS")
        if control["relay"]["public_url"] != "wss://" + context["relay_domain"] + "/relay/udp/v2":
            raise ValueError("Rendered relay URL must use versioned UDP bridge")
        if relay["server"]["udp_advertise_host"] != context["relay_domain"]:
            raise ValueError("Rendered relay advertised host differs from routing")
        references = {
            v.removeprefix("/run/secrets/")
            for doc in (control, relay)
            for table in doc.values()
            for v in table.values()
            if isinstance(v, str) and v.startswith("/run/secrets/")
        }
        if references != RUNTIME_SECRETS - {"relay_tls_ca", "dns_provider_token"}:
            raise ValueError("Rendered TOML runtime secret references are incomplete")
        routes, traefik = documents["proxy-routes.toml"], documents["traefik.toml"]
        transport = routes["http"]["serversTransports"]["relay"]
        if transport != {"serverName": "relay", "rootCAs": ["/run/secrets/relay_tls_ca"]}:
            raise ValueError("Rendered proxy must authenticate backend TLS")
        for name in ("control", "relay"):
            router = routes["http"]["routers"][name]
            if router["rule"] != f"Host(`{context[name + '_domain']}`)" or router["tls"] != {
                "certResolver": "public"
            }:
                raise ValueError("Rendered production routers require public ACME and correct DNS")
        acme = traefik["certificatesResolvers"]["public"]["acme"]
        if (
            acme["email"] != context["acme_email"]
            or acme["dnsChallenge"]["provider"] != context["dns_provider"]
        ):
            raise ValueError("Production DNS-01 wiring differs from supplied operator settings")
        # This checker owns its production fixture. Do not inherit the local
        # developer/integration fixture's ports or private-state paths.
        env = dict(
            os.environ,
            CONTROL_DOMAIN=context["control_domain"],
            RELAY_DOMAIN=context["relay_domain"],
            RUNTIME_UID="65532",
            RUNTIME_GID="65532",
            CONTROL_CONFIG=str(temp / "control.toml"),
            RELAY_CONFIG=str(temp / "relay.toml"),
            TRAEFIK_CONFIG=str(temp / "traefik.toml"),
        )
        services = render([ROOT / "deploy/compose.yaml", temp / "compose.production.yaml"], env)[
            "services"
        ]
        for name, service in services.items():
            if ("dns_provider_token" in secrets(service)) != (name == "traefik"):
                raise ValueError("DNS credential must be exclusive to Traefik")
        proxy = services["traefik"]
        if (
            secrets(proxy) != {"relay_tls_ca", "dns_provider_token"}
            or proxy["environment"] != context["dns_provider_file_environment"]
        ):
            raise ValueError(
                "Production provider credential must use only mounted _FILE references"
            )
        ansible_env = {
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(temp / "ansible-tmp"),
            "ANSIBLE_HOME": str(temp / "ansible-home"),
            "ANSIBLE_CONFIG": str(playbook.parent / "ansible.cfg"),
        }
        result = subprocess.run(
            [
                "ansible-playbook",
                "--syntax-check",
                "-i",
                str(playbook.parent / "inventory.example.ini"),
                str(playbook),
            ],
            env=ansible_env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise ValueError("Ansible syntax check failed: " + result.stderr)
    print("Ansible bundle, rendered TOML/Compose, permissions and DNS-01 wiring are valid")


if __name__ == "__main__":
    raise SystemExit(cli(main))
