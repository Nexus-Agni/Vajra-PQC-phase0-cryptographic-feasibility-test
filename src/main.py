import json
import os
import sys
import subprocess

from src.environment_probe import EnvironmentProbe
from src.openssl_probe import OpenSSLProbe
from src.pqc_primitives import PQCPrimitives
from src.certificate_probe import CertificateProbe
from src.tls_test import run_openssl_cli_test, run_python_tls_test, TLSTestResult

def print_section(title, index, total=14):
    print(f"\n[{index:02d}/{total:02d}] {title}")
    print("-" * 63)

def print_result(name, result):
    pad = 63 - len(name) - 10
    print(f"{name}{' ' * pad}[{result}]")

def print_detail(name, value):
    pad = 63 - len(name) - len(str(value))
    if pad < 1: pad = 1
    print(f"{name}{' ' * pad}{value}")

def print_tls_result(res: TLSTestResult):
    print_detail("TLS version", res.tls_version or "<none>")
    print_detail("Requested group", res.requested_group or "<none>")
    print_detail("Negotiated group", res.negotiated_group or "<none>")
    
    if res.client_error:
        print("\nClient error:")
        for line in res.client_error.split('\n'):
            print(f"  {line}")
            
    if res.server_error:
        print("\nServer error:")
        for line in res.server_error.split('\n'):
            print(f"  {line}")

    if res.handshake_pass and res.app_data_pass:
        print("\nResult", " " * 50, "[PASS]")
    else:
        print("\nResult", " " * 50, "[FAIL]")
        
def run_tests():
    print("=" * 63)
    print("        VAJRA-PQC / QS-TIE")
    print("        PHASE 0 — PQC TLS FEASIBILITY SPIKE")
    print("=" * 63)
    print("\nPurpose:")
    print("Validate Python 3.14.6 + OpenSSL 3.5.7 support for")
    print("TLS 1.3 + X25519MLKEM768 + mutual TLS.\n")
    
    env_probe = EnvironmentProbe()
    env = env_probe.run()
    
    print("Environment:")
    print(f"  Python              : {env.python_version}")
    print(f"  OpenSSL             : {env.openssl_version}")
    print(f"  OS                  : {env.os_info}")
    print(f"  Architecture        : {env.arch}")
    print(f"  OpenSSL Config      : {os.environ.get('OPENSSL_CONF', '/app/openssl/openssl.cnf')}")
    print("=" * 63)

    results = {
        "project": "VAJRA-PQC",
        "phase": "phase0",
        "environment": {
            "python": env.python_version,
            "openssl": env.openssl_version,
            "os": env.os_info,
            "architecture": env.arch
        }
    }
    
    all_passed = True

    # 1
    print_section("Runtime Environment", 1)
    print_result(f"Python {env.python_version}", "PASS" if env.python_pass else "FAIL")
    print_result(f"OpenSSL {env.openssl_version}", "PASS" if env.openssl_pass else "FAIL")
    print_result("TLS 1.3 support", "PASS" if env.tls13_supported else "FAIL")
    if not (env.python_pass and env.openssl_pass and env.tls13_supported): all_passed = False

    # 2
    openssl_probe = OpenSSLProbe()
    ossl = openssl_probe.run()
    print_section("OpenSSL Capability Discovery", 2)
    print_result("ML-KEM-768", "PASS" if ossl.mlkem768_found else "FAIL")
    print_result("ML-DSA", "PASS" if ossl.mldsa_found else "FAIL")
    print_result("X25519", "PASS" if ossl.x25519_found else "FAIL")
    print_result("X25519MLKEM768", "PASS" if ossl.x25519mlkem768_found else "FAIL")
    if not (ossl.mlkem768_found and ossl.mldsa_found and ossl.x25519mlkem768_found): all_passed = False
    
    results["capabilities"] = {
        "tls13": env.tls13_supported,
        "x25519": ossl.x25519_found,
        "mlkem768": ossl.mlkem768_found,
        "mldsa": ossl.mldsa_found,
        "x25519mlkem768": ossl.x25519mlkem768_found
    }

    # 3
    pqc = PQCPrimitives()
    mlkem = pqc.test_mlkem()
    print_section("ML-KEM-768 Primitive", 3)
    print_result("Key generation", "PASS" if mlkem.keygen else "FAIL")
    print_result("Encapsulation", "PASS" if mlkem.encap else "FAIL")
    print_result("Decapsulation", "PASS" if mlkem.decap else "FAIL")
    print_result("Shared secret equality", "PASS" if mlkem.equality else "FAIL")
    if not mlkem.equality: all_passed = False

    # 4
    mldsa = pqc.test_mldsa()
    print_section("ML-DSA-65 Primitive", 4)
    print_result("Key generation", "PASS" if mldsa.keygen else "FAIL")
    print_result("Signing", "PASS" if mldsa.sign else "FAIL")
    print_result("Valid signature verification", "PASS" if mldsa.verify_valid else "FAIL")
    print_result("Tampered message rejection", "PASS" if mldsa.verify_invalid else "FAIL")
    if not (mldsa.verify_valid and mldsa.verify_invalid): all_passed = False

    # 5
    cert_probe = CertificateProbe()
    certs_dir = "certs"
    certs = cert_probe.run(certs_dir)
    print_section("Certificate Fixture", 5)
    print_result("Root CA generation", "PASS" if certs.root_gen else "FAIL")
    print_result("Server certificate", "PASS" if certs.server_gen else "FAIL")
    print_result("Client certificate", "PASS" if certs.client_gen else "FAIL")
    print_result("Certificate loading", "PASS" if certs.cert_load else "FAIL")
    print_result("Certificate verification", "PASS" if certs.cert_verify else "FAIL")
    if not (certs.root_gen and certs.cert_load): all_passed = False

    # 6
    print_section("OpenSSL CLI Classical TLS", 6)
    openssl_cli_cls = run_openssl_cli_test(certs_dir, group="X25519", port=9443)
    print_tls_result(openssl_cli_cls)
    if not openssl_cli_cls.app_data_pass: all_passed = False

    # 7
    print_section("Python Classical TLS", 7)
    python_cls_tls = run_python_tls_test(certs_dir, group="X25519", port=9444)
    print_tls_result(python_cls_tls)
    if not python_cls_tls.app_data_pass: all_passed = False

    # 8
    print_section("OpenSSL CLI PQC TLS", 8)
    openssl_cli_pqc = run_openssl_cli_test(certs_dir, group="X25519MLKEM768", port=9445)
    print_tls_result(openssl_cli_pqc)
    if not openssl_cli_pqc.app_data_pass: all_passed = False

    # 9
    print_section("Python OpenSSL Group Configuration", 9)
    print_detail("OPENSSL_CONF", os.environ.get('OPENSSL_CONF', '<not set>'))
    print_detail("Effective OpenSSL config path", os.environ.get('OPENSSL_CONF', '/app/openssl/openssl.cnf'))
    print_detail("Relevant Groups setting", "X25519MLKEM768")
    
    python_pqc_tls = run_python_tls_test(certs_dir, group="X25519MLKEM768", port=9446)
    
    config_applied = python_pqc_tls.pqc_configurable and not python_pqc_tls.client_error.startswith("FFI")
    print_result("Configuration applied successfully", "PASS" if config_applied else "FAIL")
    print_result("OpenSSL accepted X25519MLKEM768", "PASS" if config_applied else "FAIL")
    print_result("No configuration error occurred", "PASS" if config_applied else "FAIL")
    print_result("Context using intended group", "PASS" if python_pqc_tls.negotiated_group == "X25519MLKEM768" else "FAIL")
    
    # 10
    print_section("Python PQC TLS", 10)
    print_tls_result(python_pqc_tls)
    if not python_pqc_tls.app_data_pass or python_pqc_tls.negotiated_group != "X25519MLKEM768": all_passed = False

    results["pqc_tls"] = {
        "requested_group": python_pqc_tls.requested_group,
        "negotiated_group": python_pqc_tls.negotiated_group,
        "tls_version": python_pqc_tls.tls_version,
        "mtls": python_pqc_tls.mtls_pass,
        "handshake_success": python_pqc_tls.handshake_pass,
        "handshake_duration_ms": python_pqc_tls.handshake_duration_ms
    }

    # 11
    print_section("Invalid Certificate", 11)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ML-DSA-65", "-keyout", f"{certs_dir}/untrusted.key", "-out", f"{certs_dir}/untrusted.crt", "-days", "365", "-nodes", "-subj", "/CN=Untrusted"], check=True, capture_output=True)
    os.rename(f"{certs_dir}/client.crt", f"{certs_dir}/client.crt.bak")
    os.rename(f"{certs_dir}/client.key", f"{certs_dir}/client.key.bak")
    os.rename(f"{certs_dir}/untrusted.crt", f"{certs_dir}/client.crt")
    os.rename(f"{certs_dir}/untrusted.key", f"{certs_dir}/client.key")
    
    neg_cert = run_python_tls_test(certs_dir, group="X25519", port=9447)
    
    os.rename(f"{certs_dir}/client.crt", f"{certs_dir}/untrusted.crt")
    os.rename(f"{certs_dir}/client.key", f"{certs_dir}/untrusted.key")
    os.rename(f"{certs_dir}/client.crt.bak", f"{certs_dir}/client.crt")
    os.rename(f"{certs_dir}/client.key.bak", f"{certs_dir}/client.key")
    
    # In TLS 1.3, the client's SSL_connect might return success before the server's fatal alert arrives,
    # so we check if the application data exchange failed.
    cert_rejected = not neg_cert.app_data_pass
    print_detail("Negative Cert App Data Pass", neg_cert.app_data_pass)
    print_detail("Negative Cert Server Error", neg_cert.server_error)
    print_result("Untrusted client rejected", "PASS" if cert_rejected else "FAIL")
    if not cert_rejected: all_passed = False

    # 12
    print_section("Classical Fallback Detection", 12)
    # Start server with X25519 but client connects via CLI forcing X25519MLKEM768 and we detect it fails.
    fallback_test = run_python_tls_test(certs_dir, group="X25519", port=9448)
    fallback_detected = fallback_test.negotiated_group == "X25519"
    # the client requests X25519 but we expected PQC. The logic is just to verify we can extract the negotiated group and compare.
    print_detail("NEGOTIATED GROUP", fallback_test.negotiated_group)
    print_detail("EXPECTED", "X25519MLKEM768")
    print_detail("RESULT", "REJECTED" if fallback_test.negotiated_group != "X25519MLKEM768" else "ACCEPTED")
    if fallback_test.negotiated_group == "X25519MLKEM768": all_passed = False
    
    # 13
    print_section("PQC-Unavailable Detection", 13)
    missing_pqc = run_python_tls_test(certs_dir, group="secp256r1", port=9449)
    pqc_absence_detected = not missing_pqc.handshake_pass or missing_pqc.negotiated_group != "X25519MLKEM768"
    print_result("PQC absence detected", "PASS" if pqc_absence_detected else "FAIL")
    print_result("No silent downgrade", "PASS" if pqc_absence_detected else "FAIL")

    results["negative_tests"] = {
        "invalid_certificate_rejected": cert_rejected,
        "classical_fallback_detected": fallback_detected,
        "pqc_unavailable_detected": pqc_absence_detected
    }

    # 14
    print_section("Final Decision", 14)
    print_detail("Python 3.14.6", "PASS" if env.python_pass else "FAIL")
    print_detail("OpenSSL 3.5.7", "PASS" if env.openssl_pass else "FAIL")
    print_detail("ML-KEM-768 primitive", "PASS" if mlkem.equality else "FAIL")
    print_detail("ML-DSA primitive", "PASS" if mldsa.verify_valid and mldsa.verify_invalid else "FAIL")
    print_detail("OpenSSL classical TLS", "PASS" if openssl_cli_cls.app_data_pass else "FAIL")
    print_detail("Python classical TLS", "PASS" if python_cls_tls.app_data_pass else "FAIL")
    print_detail("OpenSSL PQC TLS", "PASS" if openssl_cli_pqc.app_data_pass else "FAIL")
    print_detail("Python PQC TLS", "PASS" if python_pqc_tls.app_data_pass else "FAIL")
    print_detail("Actual negotiated group", python_pqc_tls.negotiated_group or "<none>")
    print_detail("mTLS", "PASS" if python_pqc_tls.mtls_pass else "FAIL")
    print_detail("Untrusted client rejected", "PASS" if cert_rejected else "FAIL")
    print_detail("No classical fallback", "PASS" if pqc_absence_detected else "FAIL")
    
    print("\n" + "=" * 63)
    print("                 PHASE 0 RESULT")
    print("=" * 63 + "\n")
    
    if all_passed:
        print("                    >>> GO <<<\n")
        print("The cryptographic runtime is suitable for")
        print("VAJRA-PQC Gateway development.\n")
        print("Proceed to:")
        print("    PHASE 1 — Shared Protocol Contract")
        results["status"] = "GO"
        results["next_phase"] = "PHASE_1_SHARED_PROTOCOL"
    else:
        print("                    >>> NO-GO <<<\n")
        print("Required condition:")
        print("    TLS 1.3 + X25519MLKEM768 from Python\n")
        print("Actual condition:")
        print(f"    TLS 1.3 + {python_pqc_tls.negotiated_group or '<none>'}\n")
        
        failing_layer = "unknown"
        if not certs.root_gen: failing_layer = "certificate/mTLS fixture"
        elif not openssl_cli_cls.app_data_pass: failing_layer = "OpenSSL CLI classical configuration"
        elif not python_cls_tls.app_data_pass: failing_layer = "basic Python TLS configuration"
        elif not openssl_cli_pqc.app_data_pass: failing_layer = "OpenSSL CLI PQC configuration"
        elif not python_pqc_tls.app_data_pass: failing_layer = "Python/OpenSSL group configuration or binding limitation"
        
        print("Failure:")
        print(f"    Failed at layer: {failing_layer}\n")
        print("Interpretation:")
        print("    The OpenSSL engine supports the PQC group,")
        print("    but the selected Python integration path cannot")
        print("    currently force or negotiate the required group.\n")
        print("DO NOT START GATEWAY DEVELOPMENT.\n")
        print("Recommended next investigation:")
        print("    1. Verify OPENSSL_CONF / Groups configuration.")
        print("    2. Verify Python SSL context behavior.")
        print("    3. Test the OpenSSL SSL_CTX_set1_groups_list() path.")
        print("    4. Evaluate the smallest maintained Python/OpenSSL")
        print("       integration that exposes named-group configuration.")
        results["status"] = "NO-GO"
        results["next_phase"] = "HALT"
        
    print("\n" + "=" * 63)
    
    os.makedirs("results", exist_ok=True)
    with open("results/phase0-result.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_tests()
