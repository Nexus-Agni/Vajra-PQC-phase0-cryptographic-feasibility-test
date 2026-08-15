from src.certificate_probe import CertificateProbe

def test_certificates():
    res = CertificateProbe().run("certs")
    assert res.root_gen
    assert res.server_gen
    assert res.client_gen
    assert res.cert_load
    assert res.cert_verify
