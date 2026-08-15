import subprocess
from dataclasses import dataclass

@dataclass
class OpenSSLProbeResult:
    mlkem768_found: bool
    mldsa_found: bool
    x25519_found: bool
    x25519mlkem768_found: bool

class OpenSSLProbe:
    def run(self) -> OpenSSLProbeResult:
        try:
            groups_out = subprocess.check_output(["openssl", "list", "-tls1_3", "-tls-groups"], text=True)
            kems_out = subprocess.check_output(["openssl", "list", "-kem-algorithms"], text=True)
            sigs_out = subprocess.check_output(["openssl", "list", "-signature-algorithms"], text=True)
        except subprocess.CalledProcessError:
            return OpenSSLProbeResult(False, False, False, False)

        mlkem = "ML-KEM-768" in kems_out or "MLKEM768" in kems_out
        mldsa = "ML-DSA-65" in sigs_out or "ML-DSA" in sigs_out
        x25519 = "X25519" in groups_out
        x25519mlkem768 = "X25519MLKEM768" in groups_out

        return OpenSSLProbeResult(
            mlkem768_found=mlkem,
            mldsa_found=mldsa,
            x25519_found=x25519,
            x25519mlkem768_found=x25519mlkem768
        )
