from src.tls_test import run_tls_test

def test_pqc_tls():
    res = run_tls_test("certs", group="X25519MLKEM768", port=9502)
    assert res.tls_version == "TLSv1.3"
    assert res.negotiated_group == "X25519MLKEM768"
    assert res.mtls_pass
    assert res.app_data_pass
