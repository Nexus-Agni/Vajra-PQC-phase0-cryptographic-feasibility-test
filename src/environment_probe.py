import sys
import ssl
import platform
import os
from dataclasses import dataclass

@dataclass
class EnvironmentResult:
    python_version: str
    openssl_version: str
    os_info: str
    arch: str
    tls13_supported: bool
    python_pass: bool
    openssl_pass: bool

class EnvironmentProbe:
    def run(self) -> EnvironmentResult:
        py_ver = sys.version.split()[0]
        ssl_ver = ssl.OPENSSL_VERSION
        os_info = platform.platform()
        arch = platform.machine()
        tls13 = getattr(ssl, "HAS_TLSv1_3", False)

        py_pass = py_ver == "3.14.6"
        ssl_pass = "3.5.7" in ssl_ver

        return EnvironmentResult(
            python_version=py_ver,
            openssl_version=ssl_ver,
            os_info=os_info,
            arch=arch,
            tls13_supported=tls13,
            python_pass=py_pass,
            openssl_pass=ssl_pass
        )
