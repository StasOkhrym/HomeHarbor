"""Validate local and isolated Compose contracts without creating keys or state."""

import json
import os
import shlex
import subprocess
import tomllib

from tooling import ROOT, cli, require_commands


def render(files, env):
    args = ["docker", "compose"]
    for path in files:
        args.extend(["-f", str(path)])

    result = subprocess.run(
        [*args, "config", "--format", "json"], env=env, capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise ValueError("Compose render failed: " + result.stderr.strip())

    return json.loads(result.stdout)


def secrets(service):
    return {item["source"] for item in service.get("secrets", [])}


def validate(services, integration):
    expected_control = {
        "postgres_password",
        "redis_password",
        "session_signing_key",
        "ceremony_encryption_key",
        "relay_ticket_key",
        "root_public_key",
    }
    if secrets(services["control"]) != expected_control:
        raise ValueError("control must receive exactly its runtime secrets")
    if secrets(services["migrate"]) != {"postgres_password"}:
        raise ValueError("migrate must receive only the database password")
    if secrets(services["relay"]) != {
        "relay_ticket_key",
        "relay_tls_cert",
        "relay_tls_key",
        "relay_tls_ca",
    }:
        raise ValueError("relay must receive only its ticket and TLS secrets")
    if services["redis"].get("ports"):
        raise ValueError("Redis must remain private in the local stack")
    if services["db"].get("ports"):
        raise ValueError("Database must remain private in the local stack")
    if services["relay"].get("ports"):
        raise ValueError("Local relay must not publish UDP ports")

    for service in services.values():
        if service.get("privileged") or service.get("cap_add"):
            raise ValueError("Backend development must not acquire network capabilities")
        if service.get("network_mode") == "host":
            raise ValueError("Backend development must use isolated Docker networking")

    proxy = services["traefik"]
    if (
        set(proxy.get("cap_drop", [])) != {"ALL"}
        or proxy.get("cap_add")
        or not proxy.get("read_only")
    ):
        raise ValueError("proxy must be read-only with all capabilities dropped")
    if not proxy.get("user") or proxy["user"].split(":")[0] in ("0", "root"):
        raise ValueError("proxy must run as a non-root user")
    if any("docker.sock" in str(mount) for mount in proxy.get("volumes", [])):
        raise ValueError("proxy must not receive the Docker socket")
    if secrets(proxy) != {"relay_tls_ca", "frontend_tls_cert", "frontend_tls_key"}:
        raise ValueError("Local proxy must receive only backend CA and frontend TLS pair")

    ports = proxy.get("ports", [])
    if not ports or any(port.get("host_ip") != "127.0.0.1" for port in ports):
        raise ValueError("Local proxy must bind only to loopback")

    for name, service in services.items():
        if name != "traefik" and secrets(service) & {"frontend_tls_cert", "frontend_tls_key"}:
            raise ValueError("Frontend TLS must be exclusive to local Traefik")

    dynamic = tomllib.loads((ROOT / "deploy/traefik/routes.toml").read_text())
    transport = dynamic["http"]["serversTransports"]["relay"]
    if (
        transport.get("insecureSkipVerify")
        or transport.get("serverName") != "relay"
        or transport.get("rootCAs") != ["/run/secrets/relay_tls_ca"]
    ):
        raise ValueError("proxy must authenticate relay TLS using CA and server name")

    for router in dynamic["http"]["routers"].values():
        if "certResolver" in router.get("tls", {}):
            raise ValueError("Local routing must not request public certificates")

    if set(integration) != {"postgres", "redis"}:
        raise ValueError("integration stack must contain only PostgreSQL and Redis")

    for name, service in integration.items():
        ports = service.get("ports", [])
        if not ports or any(port.get("host_ip") != "127.0.0.1" for port in ports):
            raise ValueError(f"integration {name} ports must bind only to loopback")

    for redis in (services["redis"], integration["redis"]):
        if secrets(redis) != {"redis_password"}:
            raise ValueError("Redis must receive only its password secret")

        command = "\n".join(redis.get("command", []))
        tokens = shlex.split(command)
        for flag, value in (
            ("--maxmemory", "128mb"),
            ("--maxmemory-policy", "noeviction"),
            ("--aclfile", "/tmp/users.acl"),
        ):
            if flag not in tokens or tokens[tokens.index(flag) + 1] != value:
                raise ValueError(f"Redis must use {flag} {value}")

        if "/run/secrets/redis_password" not in command or "sha256sum" not in tokens:
            raise ValueError("Redis ACL must hash the file credential")
        if str(redis.get("mem_limit")) != "268435456":
            raise ValueError("Redis must have a 256 MiB container memory limit")

        health = " ".join(redis.get("healthcheck", {}).get("test", []))
        if (
            "REDISCLI_AUTH" not in health
            or "/run/secrets/redis_password" not in health
            or "PONG" not in health
        ):
            raise ValueError("Redis healthcheck must authenticate and require PONG")

    print("Compose SQL/Redis secret boundaries and limits are valid")


def environment():
    return {
        **os.environ,
        "CONTROL_DOMAIN": "control.localhost",
        "RELAY_DOMAIN": "relay.localhost",
        "CONTROL_CONFIG": "../config/control.example.toml",
        "RELAY_CONFIG": "../config/relay.example.toml",
        "TRAEFIK_CONFIG": "./traefik/local.toml",
        "TRAEFIK_DYNAMIC_DIR": "../.local/traefik/dynamic",
        "TRAEFIK_STATE_DIR": "../.local/traefik/state",
        "RUNTIME_UID": "65532",
        "RUNTIME_GID": "65532",
        "INTEGRATION_POSTGRES_PORT": "55432",
        "INTEGRATION_REDIS_PORT": "56379",
    }


def main():
    require_commands("docker")
    env = environment()
    base = ROOT / "deploy/compose.yaml"
    local = render([base], env)["services"]
    integration = render([ROOT / "deploy/compose.integration.yaml"], env)["services"]
    validate(local, integration)
    print("Local and integration Compose contracts are valid")


if __name__ == "__main__":
    raise SystemExit(cli(main))
