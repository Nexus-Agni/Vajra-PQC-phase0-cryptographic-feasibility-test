# VAJRA-PQC / QS-TIE — Phase 0 Cryptographic Feasibility Spike

This Phase 0 feasibility spike validates the cryptographic runtime foundation for the VAJRA-PQC / QS-TIE prototype.
The objective is to establish whether a Python 3.14.6 application, linked to OpenSSL 3.5.7, can successfully negotiate a TLS 1.3 connection using the hybrid post-quantum group `X25519MLKEM768`.

## Why X25519MLKEM768 Matters
In Phase 1+, the QS-TIE gateway needs to establish secure communication between threat intelligence simulated environments using post-quantum cryptography. `X25519MLKEM768` is a hybrid key exchange mechanism providing both classical and post-quantum security guarantees against "harvest now, decrypt later" attacks, which is the core requirement of the thesis.

## Pinned Versions
* **Python 3.14.6**: The target version for the microservice architecture, chosen for compatibility and modern async/network features.
* **OpenSSL 3.5.7**: Required because native support for ML-KEM and hybrid groups like `X25519MLKEM768` was introduced in the 3.5 release line, and 3.5.7 represents the specific patched target for our environment.

## Execution
To run the feasibility spike:

```bash
docker compose build
docker compose run --rm phase0
```

## Interpreting Results
The runner will output either a `GO` or `NO-GO` decision.

* **GO**: Indicates that all cryptographic primitives, classical TLS control, and PQC TLS requirements are successfully satisfied. Python can successfully negotiate the `X25519MLKEM768` group without fallback. We can proceed to Phase 1.
* **NO-GO**: Indicates a failure at some level of the required stack. Do not proceed to Gateway development until the underlying runtime can guarantee PQC negotiation. The failure report will detail whether the issue stems from OpenSSL limitations, Python binding issues, or classical downgrades.
