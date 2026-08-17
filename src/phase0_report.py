import json
import os
from dataclasses import dataclass, asdict
from typing import Optional

def write_evidence(filename: str, content: str):
    path = f"/app/artifacts/evidence/{filename}"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return path

@dataclass
class EnvironmentInfo:
    python_implementation: str
    python_version: str
    python_executable: str
    python_architecture: str
    ssl_module_path: str
    _ssl_module_path: str
    ssl_openssl_version: str
    ssl_openssl_version_number: str
    openssl_cli_path: str
    openssl_cli_version: str
    libssl_path: Optional[str]
    libcrypto_path: Optional[str]
    libssl_sha256: Optional[str]
    libcrypto_sha256: Optional[str]
    os_info: str
    kernel: str
    container_image: str

@dataclass
class OpenSSLCapabilityResult:
    x25519_mlkem768_present: bool
    evidence_path: str

@dataclass
class CtypesPqcTlsResult:
    handshake_pass: bool
    app_data_pass: bool
    negotiated_group: Optional[str]
    mtls_pass: bool
    client_error: str
    server_error: str
    evidence_path: str

@dataclass
class ShimSafetyResult:
    python_build_validated: bool
    architecture_validated: bool
    ssl_ctx_extraction_validated: bool
    ssl_ctx_pointer_validated: bool
    documented_api_used: bool
    fail_closed_guard_active: bool
    pass_status: bool
    error: str

@dataclass
class NativeGroupConfigResult:
    context_accessible: bool
    ssl_ctx_pointer_valid: bool
    api_available: bool
    api_return_value: Optional[int]
    configured: bool
    error: Optional[str]
    evidence_path: str

@dataclass
class AsyncioPqcTlsResult:
    server_started: bool
    client_connected: bool
    handshake_pass: bool
    app_data_pass: bool
    negotiated_group: Optional[str]
    error: Optional[str]
    evidence_path: str

@dataclass
class PythonPqcTlsResult:
    handshake_pass: bool
    app_data_pass: bool
    negotiated_group: Optional[str]
    error: Optional[str]
    evidence_path: str

class Report:
    def __init__(self):
        self.data = {
            "metadata": {"project": "VAJRA-PQC", "phase": "0_final_validation"},
            "environment": None,
            "openssl_capability": None,
            "native_openssl": None,
            "python_classical_control": None,
            "python_stdlib_pqc_control": None,
            "sslcontext_bridge": None,
            "python_sslcontext_pqc": None,
            "asyncio_classical": None,
            "asyncio_pqc": None,
            "mtls_negative": None,
            "fallback_controls": None,
            "repeatability": None,
            "shim_safety": None,
            "decision": None
        }

    def set(self, key, value):
        if hasattr(value, "__dataclass_fields__"):
            self.data[key] = asdict(value)
        else:
            self.data[key] = value

    def save(self, path="/app/artifacts/phase0_report.json"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.data, f, indent=2)

        # Also save environment specifically
        if self.data["environment"]:
            env_path = "/app/artifacts/phase0_environment.json"
            with open(env_path, "w") as f:
                json.dump(self.data["environment"], f, indent=2)

    def generate_thesis_summary(self, path="/app/artifacts/phase0_thesis_summary.md"):
        env = self.data["environment"]
        decision = self.data["decision"]
        
        summary = f"""# VAJRA-PQC / QS-TIE Phase 0 Feasibility Summary

## Objective
Phase 0 attempted to prove that the proposed Gateway A/B architecture (Python 3.14.6 + asyncio + ssl.SSLContext) can successfully negotiate TLS 1.3 X25519MLKEM768 using OpenSSL 3.5.7, aided by a minimal native OpenSSL supported-groups configuration shim.

## Environment
- Python Version: {env.get('python_version')}
- OpenSSL Version: {env.get('openssl_cli_version')}
- libssl.so Hash: {env.get('libssl_sha256')}

## Tests
| Layer | Test | Expected | Actual | Evidence | Result |
| ----- | ---- | -------- | ------ | -------- | ------ |
"""
        tests = [
            ("OpenSSL", "PQC Support", "PASS", "PASS" if self.data["openssl_capability"]["x25519_mlkem768_present"] else "FAIL", "01_openssl_groups.txt", "PASS" if self.data["openssl_capability"]["x25519_mlkem768_present"] else "FAIL"),
            ("Native CTypes", "PQC Negotiation", "PASS", "PASS" if self.data["native_openssl"]["app_data_pass"] else "FAIL", "03_native_negotiation.txt", "PASS" if self.data["native_openssl"]["app_data_pass"] else "FAIL"),
            ("Python stdlib", "Classical Control", "PASS", "PASS" if self.data["python_classical_control"]["app_data_pass"] else "FAIL", "04_python_classical.txt", "PASS" if self.data["python_classical_control"]["app_data_pass"] else "FAIL"),
            ("Python stdlib", "set_ecdh_curve limitation", "FAIL", "FAIL", "05_python_stdlib_pqc_control.txt", "PASS" if self.data["python_stdlib_pqc_control"]["error"] else "FAIL"),
            ("Bridge", "SSLContext shim config", "PASS", "PASS" if self.data["sslcontext_bridge"]["configured"] else "FAIL", "06_sslcontext_bridge.txt", "PASS" if self.data["sslcontext_bridge"]["configured"] else "FAIL"),
            ("Python SSLContext", "PQC Handshake", "PASS", "PASS" if self.data["python_sslcontext_pqc"]["app_data_pass"] else "FAIL", "07_python_sslcontext_pqc.txt", "PASS" if self.data["python_sslcontext_pqc"]["app_data_pass"] else "FAIL"),
            ("Asyncio", "PQC Handshake", "PASS", "PASS" if self.data["asyncio_pqc"]["app_data_pass"] else "FAIL", "09_asyncio_pqc.txt", "PASS" if self.data["asyncio_pqc"]["app_data_pass"] else "FAIL")
        ]
        
        for layer, test, exp, act, ev, res in tests:
            summary += f"| {layer} | {test} | {exp} | {act} | {ev} | {res} |\n"

        summary += f"""
## Decision
FINAL DECISION: {decision.get('status')}

{decision.get('reason')}

## Implementation consequence
"""
        if decision.get('status') == "GO":
            summary += """Gateway A/B may proceed using:

Python 3.14.6
asyncio
ssl.SSLContext
OpenSSL 3.5.7
minimal validated compatibility shim
SSL_CTX_set1_groups_list("X25519MLKEM768")
"""
        else:
            summary += f"Gateway implementation is blocked because: {decision.get('reason')}\n"
            
        summary += """
## Limitations
- Python stdlib does not directly expose the required PQC-group configuration through `set_ecdh_curve()`;
- compatibility shim is tied to the validated CPython/OpenSSL environment;
- it relies on the internal `PySSLContext` struct layout representing `SSL_CTX*` directly after `PyObject_HEAD`;
- no direct negotiated group introspection via public `ssl.SSLSocket` APIs was possible without OpenSSL native extraction, requiring proof-by-construction fallback;
- no production PKI/HSM claims are made by Phase 0.
"""
        with open(path, "w") as f:
            f.write(summary)
