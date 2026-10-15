"""Manual sandbox HTTPS fixture and a live HTTP listener outside the signed ACL."""

import hashlib
import json
import socket
import ssl
import sys
from contextlib import ExitStack, closing, contextmanager
from functools import partial
from http.client import HTTPConnection, HTTPResponse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread


@contextmanager
def listeners(directory, certificate, key, *, host="0.0.0.0", https_port=8080, http_port=8081):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    handler = partial(SimpleHTTPRequestHandler, directory=directory)

    with ExitStack() as stack:
        secure = stack.enter_context(ThreadingHTTPServer((host, https_port), handler))
        secure.socket = context.wrap_socket(secure.socket, server_side=True)
        forbidden = stack.enter_context(ThreadingHTTPServer((host, http_port), handler))
        yield secure, forbidden


def main():
    with listeners("/site", "/run/secrets/site_tls_cert", "/run/secrets/site_tls_key") as servers:
        secure, forbidden = servers
        worker = Thread(target=forbidden.serve_forever, daemon=True)
        worker.start()

        try:
            secure.serve_forever()
        finally:
            forbidden.shutdown()
            worker.join()


def check(ca="/run/secrets/site_tls_ca", *, https_port=8080, http_port=8081):
    context = ssl.create_default_context(cafile=ca)

    with socket.create_connection(("127.0.0.1", https_port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="site.sandbox.home.arpa") as connection:
            connection.sendall(b"GET / HTTP/1.0\r\nHost: site.sandbox.home.arpa\r\n\r\n")
            response = HTTPResponse(connection)
            response.begin()
            if response.status != 200:
                raise ValueError("private HTTPS fixture is not ready")

            certificate_hash = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()

    with closing(HTTPConnection("127.0.0.1", http_port, timeout=3)) as connection:
        connection.request("GET", "/")
        if connection.getresponse().status != 200:
            raise ValueError("non-profile HTTP fixture is not ready")

    return {
        "certificate_sha256": certificate_hash,
        "ca_sha256": hashlib.sha256(Path(ca).read_bytes()).hexdigest(),
    }


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        print(json.dumps(check(), sort_keys=True))
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit("usage: homeharbor-site.py [--check]")
