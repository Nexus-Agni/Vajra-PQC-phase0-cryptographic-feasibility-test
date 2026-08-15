import subprocess
import os
import tempfile
from dataclasses import dataclass

@dataclass
class MLKEMResult:
    keygen: bool
    encap: bool
    decap: bool
    equality: bool

@dataclass
class MLDSAResult:
    keygen: bool
    sign: bool
    verify_valid: bool
    verify_invalid: bool

class PQCPrimitives:
    def test_mlkem(self) -> MLKEMResult:
        with tempfile.TemporaryDirectory() as d:
            priv = os.path.join(d, "priv.pem")
            pub = os.path.join(d, "pub.pem")
            sec1 = os.path.join(d, "sec1.bin")
            sec2 = os.path.join(d, "sec2.bin")
            ct = os.path.join(d, "ct.bin")

            keygen = encap = decap = eq = False
            try:
                subprocess.run(["openssl", "genpkey", "-algorithm", "ML-KEM-768", "-out", priv], check=True, capture_output=True)
                subprocess.run(["openssl", "pkey", "-in", priv, "-pubout", "-out", pub], check=True, capture_output=True)
                keygen = True

                # Encap
                subprocess.run(["openssl", "pkeyutl", "-encap", "-inkey", pub, "-pubin", "-out", ct, "-secret", sec1], check=True, capture_output=True)
                encap = True

                # Decap
                subprocess.run(["openssl", "pkeyutl", "-decap", "-inkey", priv, "-in", ct, "-out", sec2], check=True, capture_output=True)
                decap = True

                with open(sec1, "rb") as f1, open(sec2, "rb") as f2:
                    eq = (f1.read() == f2.read())
            except subprocess.CalledProcessError:
                pass

            return MLKEMResult(keygen, encap, decap, eq)

    def test_mldsa(self) -> MLDSAResult:
        with tempfile.TemporaryDirectory() as d:
            priv = os.path.join(d, "priv.pem")
            pub = os.path.join(d, "pub.pem")
            msg = os.path.join(d, "msg.bin")
            badmsg = os.path.join(d, "badmsg.bin")
            sig = os.path.join(d, "sig.bin")

            with open(msg, "wb") as f:
                f.write(b"VAJRA-PQC")
            with open(badmsg, "wb") as f:
                f.write(b"VAJRA-PQC-TAMPERED")

            keygen = sign = v_valid = v_invalid = False
            try:
                # Need to use OpenSSL 3.5 algorithm name. Usually ML-DSA-65.
                subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", priv], check=True, capture_output=True)
                subprocess.run(["openssl", "pkey", "-in", priv, "-pubout", "-out", pub], check=True, capture_output=True)
                keygen = True

                # Sign
                subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", priv, "-rawin", "-in", msg, "-out", sig], check=True, capture_output=True)
                sign = True

                # Verify valid
                p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", msg, "-sigfile", sig], capture_output=True)
                if p.returncode == 0:
                    v_valid = True

                # Verify invalid
                p2 = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", badmsg, "-sigfile", sig], capture_output=True)
                if p2.returncode != 0:
                    v_invalid = True
            except subprocess.CalledProcessError:
                pass

            return MLDSAResult(keygen, sign, v_valid, v_invalid)
