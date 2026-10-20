"""Shared staged TLS generation and verification for dev and manual sandbox."""

import ipaddress
import re
import secrets

from tooling import quiet_run


def issue_authority(directory, subject):
    ca, key, config = [directory / name for name in ("ca", "ca-key", "ca-config")]
    if any(path.exists() or path.is_symlink() for path in (ca, key, config)):
        raise ValueError("CA staging paths already exist; refusing to replace authority")

    config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=authority\n"
        "[dn]\n[authority]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n"
    )
    quiet_run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "3650",
        "-sha256",
        "-subj",
        "/CN=" + subject,
        "-config",
        str(config),
        "-keyout",
        str(key),
        "-out",
        str(ca),
    )
    key.chmod(0o600)
    return ca, key


def ip_sans(addresses):
    """Validate before any private material or OpenSSL configuration is written."""

    values = []
    for raw in addresses:
        try:
            if not isinstance(raw, str) or "%" in raw:
                raise ValueError

            address = str(ipaddress.ip_address(raw))
        except ValueError:
            raise ValueError("TLS IP SAN must be a numeric address without a scope") from None

        if address in values:
            raise ValueError("TLS IP SAN addresses must be distinct")

        values.append(address)

    return values


def verify_pair(cert, key, ca, names, *, exact_names=False, ip_addresses=()):
    addresses = ip_sans(ip_addresses)
    purpose = ["-purpose", "sslserver"] if exact_names else []
    quiet_run("openssl", "verify", *purpose, "-CAfile", str(ca), str(cert))
    cert_public = quiet_run("openssl", "x509", "-in", str(cert), "-pubkey", "-noout")
    key_public = quiet_run("openssl", "pkey", "-in", str(key), "-pubout")
    if cert_public != key_public:
        raise ValueError(f"TLS certificate/key mismatch: {cert.name}; restore the matching pair")

    description = quiet_run("openssl", "x509", "-in", str(cert), "-noout", "-text").decode()
    # LibreSSL on macOS lacks verify_hostname. Match typed SANs, never treat a
    # DNS:192.168.x.x entry as proof of a numeric IP endpoint's identity.
    extension = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", description)
    all_sans = [item.strip() for item in extension[1].split(",")] if extension else []
    normalized = [
        "IP Address:" + str(ipaddress.ip_address(item.removeprefix("IP Address:")))
        if item.startswith("IP Address:")
        else item
        for item in all_sans
    ]
    expected = {*("DNS:" + name for name in names), *("IP Address:" + ip for ip in addresses)}
    if not expected.issubset(normalized) or (
        exact_names
        and (
            set(normalized) != expected
            or len(all_sans) != len(names) + len(addresses)
            or "CA:FALSE" not in description
            or "CA:TRUE" in description
        )
    ):
        raise ValueError(
            f"TLS domains do not match {cert.name}; restore its matching configuration"
        )


def same_authority(first, second):
    return quiet_run("openssl", "x509", "-in", str(first), "-pubkey", "-noout") == quiet_run(
        "openssl", "x509", "-in", str(second), "-pubkey", "-noout"
    )


def issue(directory, prefix, ca, ca_key, names, *, ip_addresses=()):
    addresses = ip_sans(ip_addresses)
    if not names and not addresses:
        raise ValueError("TLS leaf must name at least one DNS or IP identity")

    key, cert, csr, ext = [directory / f"{prefix}.{part}" for part in ("key", "cert", "csr", "ext")]
    quiet_run(
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-subj",
        "/CN=" + (names[0] if names else addresses[0]),
        "-keyout",
        str(key),
        "-out",
        str(csr),
    )
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName="
        + ",".join([*("DNS:" + name for name in names), *("IP:" + ip for ip in addresses)])
        + "\n"
    )
    quiet_run(
        "openssl",
        "x509",
        "-req",
        "-days",
        "365",
        "-sha256",
        "-in",
        str(csr),
        "-CA",
        str(ca),
        "-CAkey",
        str(ca_key),
        "-set_serial",
        "0x" + secrets.token_hex(16),
        "-extfile",
        str(ext),
        "-out",
        str(cert),
    )
    verify_pair(cert, key, ca, names, ip_addresses=addresses)
    return cert, key
