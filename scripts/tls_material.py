"""Shared staged TLS generation and verification for dev and manual sandbox."""

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


def verify_pair(cert, key, ca, names):
    quiet_run("openssl", "verify", "-CAfile", str(ca), str(cert))
    cert_public = quiet_run("openssl", "x509", "-in", str(cert), "-pubkey", "-noout")
    key_public = quiet_run("openssl", "pkey", "-in", str(key), "-pubout")
    if cert_public != key_public:
        raise ValueError(f"TLS certificate/key mismatch: {cert.name}; restore the matching pair")
    description = quiet_run("openssl", "x509", "-in", str(cert), "-noout", "-text").decode()
    # LibreSSL on macOS lacks verify_hostname. Local certificates use exact SANs.
    extension = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", description)
    sans = set(re.findall(r"DNS:([^,\s]+)", extension[1])) if extension else set()
    if not set(names).issubset(sans):
        raise ValueError(
            f"TLS domains do not match {cert.name}; restore its matching configuration"
        )


def issue(directory, prefix, ca, ca_key, names):
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
        "/CN=" + names[0],
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
        + ",".join("DNS:" + name for name in names)
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
    verify_pair(cert, key, ca, names)
    return cert, key
