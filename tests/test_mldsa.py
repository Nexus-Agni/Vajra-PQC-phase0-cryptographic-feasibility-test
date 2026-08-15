from src.pqc_primitives import PQCPrimitives

def test_mldsa():
    res = PQCPrimitives().test_mldsa()
    assert res.keygen
    assert res.sign
    assert res.verify_valid
    assert res.verify_invalid
