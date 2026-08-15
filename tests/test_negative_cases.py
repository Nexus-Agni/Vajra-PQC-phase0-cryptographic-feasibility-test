from src.tls_test import run_tls_test

def test_negative_invalid_cert():
    res = run_tls_test("certs", group="X25519", port=9503, client_cert_valid=False)
    assert not res.handshake_pass

def test_negative_missing_pqc():
    res = run_tls_test("certs", group="secp256r1", port=9504)
    assert not res.handshake_pass or res.negotiated_group != "X25519MLKEM768"
