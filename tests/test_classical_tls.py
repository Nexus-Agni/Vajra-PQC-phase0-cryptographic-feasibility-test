from src.tls_test import run_tls_test

def test_classical_tls():
    res = run_tls_test("certs", group="X25519", port=9501)
    assert res.tls_version == "TLSv1.3"
    assert res.negotiated_group == "X25519"
    assert res.mtls_pass
    assert res.app_data_pass
