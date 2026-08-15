from src.pqc_primitives import PQCPrimitives

def test_mlkem():
    res = PQCPrimitives().test_mlkem()
    assert res.keygen
    assert res.encap
    assert res.decap
    assert res.equality
