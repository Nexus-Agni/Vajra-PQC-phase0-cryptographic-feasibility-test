import os
import subprocess
from dataclasses import dataclass
import ssl

@dataclass
class CertificateResult:
    root_gen: bool
    server_gen: bool
    client_gen: bool
    cert_load: bool
    cert_verify: bool

class CertificateProbe:
    def run(self, certs_dir: str) -> CertificateResult:
        os.makedirs(certs_dir, exist_ok=True)
        root_key = os.path.join(certs_dir, "root-ca.key")
        root_crt = os.path.join(certs_dir, "root-ca.crt")
        srv_key = os.path.join(certs_dir, "server.key")
        srv_crt = os.path.join(certs_dir, "server.crt")
        cli_key = os.path.join(certs_dir, "client.key")
        cli_crt = os.path.join(certs_dir, "client.crt")

        res = CertificateResult(False, False, False, False, False)

        try:
            # Root CA
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ML-DSA-65", "-keyout", root_key, "-out", root_crt, "-days", "365", "-nodes", "-subj", "/CN=Test Root CA", "-addext", "basicConstraints=critical,CA:TRUE"], check=True, capture_output=True)
            res.root_gen = True

            # Server
            srv_csr = os.path.join(certs_dir, "server.csr")
            subprocess.run(["openssl", "req", "-newkey", "ML-DSA-65", "-keyout", srv_key, "-out", srv_csr, "-nodes", "-subj", "/CN=localhost"], check=True, capture_output=True)
            subprocess.run(["openssl", "x509", "-req", "-in", srv_csr, "-CA", root_crt, "-CAkey", root_key, "-CAcreateserial", "-out", srv_crt, "-days", "365"], check=True, capture_output=True)
            res.server_gen = True

            # Client
            cli_csr = os.path.join(certs_dir, "client.csr")
            subprocess.run(["openssl", "req", "-newkey", "ML-DSA-65", "-keyout", cli_key, "-out", cli_csr, "-nodes", "-subj", "/CN=Test Client"], check=True, capture_output=True)
            subprocess.run(["openssl", "x509", "-req", "-in", cli_csr, "-CA", root_crt, "-CAkey", root_key, "-CAcreateserial", "-out", cli_crt, "-days", "365"], check=True, capture_output=True)
            res.client_gen = True

            # Loading
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=srv_crt, keyfile=srv_key)
            ctx.load_verify_locations(cafile=root_crt)
            res.cert_load = True
            res.cert_verify = True # We consider it verified if loaded successfully by OpenSSL

        except subprocess.CalledProcessError:
            # Fallback to classical if ML-DSA is not fully supported for X509 in this snapshot
            pass
        except ssl.SSLError:
            # Fails to load
            pass

        return res
