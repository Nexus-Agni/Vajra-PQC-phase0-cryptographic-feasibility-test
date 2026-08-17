"""
stdlib_ssl_probe.py — decisive follow-up to Phase 0.

Tests whether Python's stdlib `ssl.SSLContext` (the API asyncio's TLS
support is actually built on) can select the X25519MLKEM768 hybrid group,
WITHOUT relying on SSLSocket.group() (Python 3.15+ only) for verification.

Verification strategy: configure the server to offer ONLY the hybrid group
(no classical fallback). If the handshake succeeds via a plain
ssl.SSLContext client using set_ecdh_curve(), the negotiated group must
have been the hybrid one — proven by construction, not introspection.

Run this against the same certs/ fixtures your Phase 0 harness already
produced (root-ca.crt, server.crt/key, client.crt/key).
"""

import socket
import ssl
import threading
import time
from dataclasses import dataclass


@dataclass
class StdlibSslResult:
    context_created: bool = False
    set_ecdh_curve_succeeded: bool = False
    set_ecdh_curve_error: str = ""
    handshake_pass: bool = False
    app_data_pass: bool = False
    handshake_error: str = ""


def _server_worker(port: int, certs_dir: str, group: str, result: StdlibSslResult, ready: threading.Event):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=f"{certs_dir}/server.crt", keyfile=f"{certs_dir}/server.key")
    ctx.load_verify_locations(cafile=f"{certs_dir}/root-ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    try:
        # Server offers ONLY this group — no classical fallback available,
        # so a successful handshake is, by construction, proof the hybrid
        # group was negotiated, with no need to introspect the result.
        ctx.set_ecdh_curve(group)
    except Exception as e:
        result.set_ecdh_curve_error = f"[server] {e}"
        ready.set()
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    ready.set()

    try:
        sock.settimeout(5.0)
        conn, _ = sock.accept()
        with ctx.wrap_socket(conn, server_side=True) as tls_conn:
            data = tls_conn.recv(1024)
            if data:
                tls_conn.sendall(b"STDLIB-SSL-PROBE-ACK")
    except Exception as e:
        result.handshake_error = f"[server] {e}"
    finally:
        sock.close()


def test_stdlib_ssl_hybrid_group(certs_dir: str = "certs", group: str = "X25519MLKEM768", port: int = 9600) -> StdlibSslResult:
    result = StdlibSslResult()
    ready = threading.Event()

    t = threading.Thread(target=_server_worker, args=(port, certs_dir, group, result, ready), daemon=True)
    t.start()
    ready.wait(timeout=5.0)

    if result.set_ecdh_curve_error:
        return result  # server-side set_ecdh_curve already failed — no point trying the client

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_cert_chain(certfile=f"{certs_dir}/client.crt", keyfile=f"{certs_dir}/client.key")
    client_ctx.load_verify_locations(cafile=f"{certs_dir}/root-ca.crt")
    client_ctx.check_hostname = False
    client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    try:
        client_ctx.set_ecdh_curve(group)
        result.set_ecdh_curve_succeeded = True
    except Exception as e:
        result.set_ecdh_curve_error = f"[client] {e}"
        return result

    result.context_created = True
    time.sleep(0.3)

    try:
        raw_sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        with client_ctx.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
            result.handshake_pass = True
            tls_sock.sendall(b"STDLIB-SSL-PROBE-TEST")
            resp = tls_sock.recv(1024)
            if resp == b"STDLIB-SSL-PROBE-ACK":
                result.app_data_pass = True
    except Exception as e:
        result.handshake_error = f"[client] {e}"

    t.join(timeout=2.0)
    return result


if __name__ == "__main__":
    print("Testing stdlib ssl.SSLContext with hybrid group (server offers ONLY the hybrid group)...\n")
    res = test_stdlib_ssl_hybrid_group()
    print(f"set_ecdh_curve() succeeded : {res.set_ecdh_curve_succeeded}")
    if res.set_ecdh_curve_error:
        print(f"  error: {res.set_ecdh_curve_error}")
    print(f"Handshake succeeded        : {res.handshake_pass}")
    if res.handshake_error:
        print(f"  error: {res.handshake_error}")
    print(f"App data exchanged         : {res.app_data_pass}")
    print()
    if res.handshake_pass and res.app_data_pass:
        print(">>> stdlib ssl.SSLContext CAN negotiate X25519MLKEM768. <<<")
        print("Gateway HLDs' PqcTlsClient/PqcTlsServer design (built on")
        print("SSLContext, asyncio-compatible) can proceed as currently written.")
    else:
        print(">>> stdlib ssl.SSLContext could NOT complete the hybrid handshake. <<<")
        print("The ctypes-based approach already proven in Phase 0 is the")
        print("fallback — budget explicit design time for asyncio integration")
        print("around it (this was NOT previously budgeted in the PID).")
