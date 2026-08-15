from src.openssl_probe import OpenSSLProbe

def test_openssl_groups():
    res = OpenSSLProbe().run()
    assert res.mlkem768_found
    assert res.mldsa_found
    assert res.x25519_found
    assert res.x25519mlkem768_found
