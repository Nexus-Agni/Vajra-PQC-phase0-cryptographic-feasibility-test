from src.environment_probe import EnvironmentProbe

def test_environment():
    res = EnvironmentProbe().run()
    assert res.python_pass
    assert res.openssl_pass
    assert res.tls13_supported
