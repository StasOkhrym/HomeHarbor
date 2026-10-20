"""Public certificate handoff only; never install trust or include private keys."""

import hashlib
import plistlib
import ssl
import uuid

from sandbox_ios_config import PROJECT


def public_handoff(control_ca: bytes, site_ca: bytes):
    payloads, documents, fingerprints = [], {}, []
    for role, pem in [("control", control_ca), ("site", site_ca)]:
        der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
        fingerprint = hashlib.sha256(der).hexdigest().upper()
        name = f"{role}-ca.pem"
        title = f"HomeHarbor iPhone {role.title()} CA"
        identifier = f"io.homeharbor.sandbox.ios.{role}.{fingerprint.lower()}"
        payloads.append(
            {
                "PayloadType": "com.apple.security.root",
                "PayloadVersion": 1,
                "PayloadIdentifier": identifier,
                "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, identifier)).upper(),
                "PayloadDisplayName": title,
                "PayloadCertificateFileName": name,
                "PayloadContent": der,
            }
        )
        documents[name] = pem
        fingerprints.append(f"{role}: {fingerprint}")

    identity = PROJECT + ":" + ":".join(fingerprints)
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "io.homeharbor.sandbox.ios.certificates",
        "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, identity)).upper(),
        "PayloadDisplayName": "HomeHarbor iPhone Sandbox CAs",
        "PayloadDescription": "Two local test CAs only. No VPN, DNS or proxy settings. Remove after testing.",
        "PayloadRemovalDisallowed": False,
        "PayloadContent": payloads,
    }
    documents["homeharbor-ios.mobileconfig"] = plistlib.dumps(profile, sort_keys=True)
    documents["fingerprints.txt"] = ("\n".join(fingerprints) + "\n").encode()

    return documents
