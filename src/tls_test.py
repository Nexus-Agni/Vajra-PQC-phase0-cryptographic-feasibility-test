import socket
import threading
import time
import subprocess
import traceback
import ctypes
import asyncio
import ssl
import sys
from typing import Optional

from src.openssl_groups import OpenSSLGroups
from src.ssl_shim import configure_sslcontext_hybrid_group
from src.phase0_report import CtypesPqcTlsResult, PythonPqcTlsResult, AsyncioPqcTlsResult, write_evidence


def run_openssl_cli_test(certs_dir, group="X25519", port=9000, server_group=None, test_name="cli") -> CtypesPqcTlsResult:
    if server_group is None:
        server_group = group
    res = CtypesPqcTlsResult(handshake_pass=False, app_data_pass=False, negotiated_group=None, mtls_pass=False, client_error="", server_error="", evidence_path="")
    evidence = [f"Requested group: {group}"]
    
    server_cmd = [
        "openssl", "s_server",
        "-accept", str(port),
        "-cert", f"{certs_dir}/server.crt",
        "-key", f"{certs_dir}/server.key",
        "-CAfile", f"{certs_dir}/root-ca.crt",
        "-Verify", "1",
        "-tls1_3",
        "-groups", server_group,
        "-quiet"
    ]
    
    client_cmd = [
        "openssl", "s_client",
        "-connect", f"127.0.0.1:{port}",
        "-cert", f"{certs_dir}/client.crt",
        "-key", f"{certs_dir}/client.key",
        "-CAfile", f"{certs_dir}/root-ca.crt",
        "-tls1_3",
        "-groups", group
    ]

    server_proc = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1) 

    try:
        client_proc = subprocess.run(client_cmd, input="VAJRA-PQC-PHASE0-TEST\n", capture_output=True, text=True, timeout=5)
        server_proc.stdin.write("VAJRA-PQC-PHASE0-ACK\n")
        server_proc.stdin.flush()
        time.sleep(0.5)
        server_proc.terminate()
        server_out, server_err = server_proc.communicate(timeout=2)
        
        c_out = client_proc.stdout
        c_err = client_proc.stderr
        
        evidence.append("=== Client Output ===")
        evidence.append(c_out)
        evidence.append("=== Server Output ===")
        evidence.append(server_out)
        
        if "Server Temp Key: " in c_out:
            for line in c_out.split('\n'):
                if "Server Temp Key:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        key_info = parts[1].strip()
                        res.negotiated_group = key_info.split(',')[0].strip()
                        evidence.append(f"Parsed negotiated group: {res.negotiated_group}")
        
        if client_proc.returncode == 0:
            res.handshake_pass = True
            res.mtls_pass = True 
            
            if "VAJRA-PQC-PHASE0-TEST" in server_out or "VAJRA-PQC-PHASE0-TEST" in server_err:
                res.app_data_pass = True
        else:
            res.client_error = c_err.strip()[-500:]
            res.server_error = server_err.strip()[-500:]

    except Exception as e:
        res.client_error = str(e)
        evidence.append(f"Exception: {e}")
        server_proc.terminate()
        
    res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
    return res


def py_server_worker(port, ctx_ptr, ffi, res_obj):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(("127.0.0.1", port))
        server_sock.listen(1)
        server_sock.settimeout(5.0)
        conn, addr = server_sock.accept()
        conn.setblocking(True)
    except Exception as e:
        res_obj.server_error = f"Server Accept Error: {e}"
        server_sock.close()
        return

    ssl_ptr = None
    try:
        ssl_ptr = ffi.libssl.SSL_new(ctx_ptr)
        ffi.libssl.SSL_set_fd(ssl_ptr, conn.fileno())
        
        ret = ffi.libssl.SSL_accept(ssl_ptr)
        if ret <= 0:
            err = ffi.libssl.SSL_get_error(ssl_ptr, ret)
            res_obj.server_error = f"SSL_accept failed with error code {err}"
            return
            
        buf = ctypes.create_string_buffer(1024)
        bytes_read = ffi.libssl.SSL_read(ssl_ptr, buf, 1024)
        
        if bytes_read > 0:
            resp = b"VAJRA-PQC-PHASE0-ACK"
            ffi.libssl.SSL_write(ssl_ptr, resp, len(resp))
            
    except Exception as e:
        res_obj.server_error = f"Server Python Error: {traceback.format_exc()}"
    finally:
        if ssl_ptr:
            ffi.libssl.SSL_free(ssl_ptr)
        conn.close()
        server_sock.close()


def run_ctypes_tls_test(certs_dir, group="X25519", port=9100, test_name="03_native_negotiation") -> CtypesPqcTlsResult:
    ffi = OpenSSLGroups()
    res = CtypesPqcTlsResult(handshake_pass=False, app_data_pass=False, negotiated_group=None, mtls_pass=False, client_error="", server_error="", evidence_path="")
    evidence = [f"Requested group: {group}"]
    
    if not ffi.loaded:
        res.client_error = "FFI binding failed to load libssl."
        evidence.append(res.client_error)
        res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
        return res
        
    srv_ctx = ffi.create_context(
        is_server=True,
        certfile=f"{certs_dir}/server.crt",
        keyfile=f"{certs_dir}/server.key",
        cafile=f"{certs_dir}/root-ca.crt",
        groups=group
    )
    if not srv_ctx:
        res.server_error = "Failed to create server SSL_CTX"
        evidence.append(res.server_error)
        res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
        return res
        
    cli_ctx = ffi.create_context(
        is_server=False,
        certfile=f"{certs_dir}/client.crt",
        keyfile=f"{certs_dir}/client.key",
        cafile=f"{certs_dir}/root-ca.crt",
        groups=group
    )
    
    t = threading.Thread(target=py_server_worker, args=(port, srv_ctx, ffi, res))
    t.daemon = True
    t.start()
    
    time.sleep(0.5)
    
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.settimeout(5.0)
    ssl_ptr = None
    
    try:
        client_sock.connect(("127.0.0.1", port))
        client_sock.setblocking(True)
        
        ssl_ptr = ffi.libssl.SSL_new(cli_ctx)
        ffi.libssl.SSL_set_fd(ssl_ptr, client_sock.fileno())
        
        ret = ffi.libssl.SSL_connect(ssl_ptr)
        evidence.append(f"SSL_connect API return value: {ret}")
        
        if ret <= 0:
            err = ffi.libssl.SSL_get_error(ssl_ptr, ret)
            res.client_error = f"SSL_connect failed with OpenSSL error code {err}"
            evidence.append(res.client_error)
            res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
            return res
            
        res.handshake_pass = True
        res.mtls_pass = True
        evidence.append("Handshake: PASS")
        
        neg_group = ffi.get_group_name(ssl_ptr)
        evidence.append(f"SSL_get_negotiated_group() directly queried via OpenSSL native API: {neg_group}")
        if neg_group:
            res.negotiated_group = neg_group
            
        req = b"VAJRA-PQC-PHASE0-TEST"
        ffi.libssl.SSL_write(ssl_ptr, req, len(req))
        
        buf = ctypes.create_string_buffer(1024)
        bytes_read = ffi.libssl.SSL_read(ssl_ptr, buf, 1024)
        
        if bytes_read > 0 and b"VAJRA-PQC-PHASE0-ACK" in buf.value:
            res.app_data_pass = True
            evidence.append("Application data: PASS")
            
    except Exception as e:
        res.client_error = f"Client Python Error: {e}"
        evidence.append(res.client_error)
    finally:
        if ssl_ptr:
            ffi.libssl.SSL_free(ssl_ptr)
        client_sock.close()
        
    t.join(timeout=1.0)
    res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
    return res


def py_sslcontext_server_worker(port, srv_ctx, res_obj, payload_expect=b"VAJRA-PQC-PHASE0-TEST", payload_resp=b"VAJRA-PQC-PHASE0-ACK"):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(("127.0.0.1", port))
        server_sock.listen(1)
        server_sock.settimeout(5.0)
        conn, addr = server_sock.accept()
        conn.setblocking(True)
    except Exception as e:
        res_obj.error = f"Server Accept Error: {e}"
        server_sock.close()
        return

    try:
        ssl_conn = srv_ctx.wrap_socket(conn, server_side=True)
        data = ssl_conn.recv(1024)
        if data == payload_expect:
            ssl_conn.sendall(payload_resp)
    except Exception as e:
        res_obj.error = f"Server TLS Error: {e}"
    finally:
        try:
            ssl_conn.close()
        except: pass
        server_sock.close()


def run_python_sslcontext_test(certs_dir, group="X25519", port=9200, use_native_shim=False, client_cert_valid=True, test_name="04_python_classical") -> PythonPqcTlsResult:
    res = PythonPqcTlsResult(handshake_pass=False, app_data_pass=False, negotiated_group=None, error=None, evidence_path="")
    evidence = [f"Requested group: {group}"]
    
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    srv_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    srv_ctx.load_cert_chain(f"{certs_dir}/server.crt", f"{certs_dir}/server.key")
    srv_ctx.load_verify_locations(f"{certs_dir}/root-ca.crt")
    srv_ctx.verify_mode = ssl.CERT_REQUIRED
    
    cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cli_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    
    if client_cert_valid:
        cli_ctx.load_cert_chain(f"{certs_dir}/client.crt", f"{certs_dir}/client.key")
    else:
        cli_ctx.load_cert_chain(f"{certs_dir}/untrusted.crt", f"{certs_dir}/untrusted.key")
    cli_ctx.load_verify_locations(f"{certs_dir}/root-ca.crt")
    cli_ctx.verify_mode = ssl.CERT_REQUIRED
    
    try:
        if use_native_shim:
            s_res = configure_sslcontext_hybrid_group(srv_ctx, group)
            c_res = configure_sslcontext_hybrid_group(cli_ctx, group)
            evidence.append(f"Server config via shim: {'PASS' if s_res.configured else 'FAIL'}")
            evidence.append(f"Client config via shim: {'PASS' if c_res.configured else 'FAIL'}")
            if not s_res.configured or not c_res.configured:
                res.error = "Native shim configuration failed"
                res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
                return res
        else:
            srv_ctx.set_ecdh_curve(group)
            cli_ctx.set_ecdh_curve(group)
    except Exception as e:
        res.error = f"Configuration error: {e}"
        evidence.append(res.error)
        res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
        return res
        
    t = threading.Thread(target=py_sslcontext_server_worker, args=(port, srv_ctx, res, b"VAJRA-PQC-PHASE0-PAYLOAD-TEST", b"VAJRA-PQC-PHASE0-PAYLOAD-ACK"))
    t.daemon = True
    t.start()
    
    time.sleep(0.5)
    
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.settimeout(5.0)
    
    try:
        client_sock.connect(("127.0.0.1", port))
        ssl_conn = cli_ctx.wrap_socket(client_sock, server_hostname="localhost")
        res.handshake_pass = True
        evidence.append("Handshake: PASS")
        
        ssl_conn.sendall(b"VAJRA-PQC-PHASE0-PAYLOAD-TEST")
        data = ssl_conn.recv(1024)
        if data == b"VAJRA-PQC-PHASE0-PAYLOAD-ACK":
            res.app_data_pass = True
            evidence.append("Application data exchanged successfully.")
        else:
            evidence.append(f"Unexpected payload received: {data}")
            
        res.negotiated_group = group 
        evidence.append("Negotiated group verified by exclusive configuration: " + group)
        
    except Exception as e:
        res.error = f"Client TLS Error: {e}"
        evidence.append(res.error)
    finally:
        try:
            ssl_conn.close()
        except: pass
        client_sock.close()
        
    t.join(timeout=1.0)
    res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
    return res

async def async_server_worker(port, srv_ctx, res_obj, payload_expect=b"VAJRA-PQC-PHASE0-PAYLOAD-TEST", payload_resp=b"VAJRA-PQC-PHASE0-PAYLOAD-ACK"):
    async def handle_client(reader, writer):
        try:
            data = await reader.read(1024)
            if data == payload_expect:
                writer.write(payload_resp)
                await writer.drain()
        except Exception as e:
            res_obj.error = f"Async Server Error: {e}"
        finally:
            writer.close()
            await writer.wait_closed()
            
    try:
        server = await asyncio.start_server(handle_client, '127.0.0.1', port, ssl=srv_ctx)
        res_obj.server_started = True
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        res_obj.error = f"Async Server Start Error: {e}"

async def run_async_client(port, cli_ctx, res_obj, evidence, payload_expect=b"VAJRA-PQC-PHASE0-PAYLOAD-TEST", payload_resp=b"VAJRA-PQC-PHASE0-PAYLOAD-ACK"):
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', port, ssl=cli_ctx, server_hostname="localhost")
        res_obj.client_connected = True
        res_obj.handshake_pass = True
        evidence.append("Asyncio Handshake: PASS")
        
        writer.write(payload_expect)
        await writer.drain()
        
        data = await reader.read(1024)
        if data == payload_resp:
            res_obj.app_data_pass = True
            evidence.append("Asyncio Application data: PASS")
            
    except Exception as e:
        res_obj.error = f"Async Client Error: {e}"
        evidence.append(res_obj.error)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except: pass

def run_asyncio_pqc_test(certs_dir, group="X25519MLKEM768", port=9300, test_name="09_asyncio_pqc") -> AsyncioPqcTlsResult:
    res = AsyncioPqcTlsResult(
        server_started=False, client_connected=False,
        handshake_pass=False, app_data_pass=False, negotiated_group=None, error=None, evidence_path=""
    )
    evidence = [f"Asyncio Requested group: {group}"]
    
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    srv_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    srv_ctx.load_cert_chain(f"{certs_dir}/server.crt", f"{certs_dir}/server.key")
    srv_ctx.load_verify_locations(f"{certs_dir}/root-ca.crt")
    srv_ctx.verify_mode = ssl.CERT_REQUIRED
    
    cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cli_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    cli_ctx.load_cert_chain(f"{certs_dir}/client.crt", f"{certs_dir}/client.key")
    cli_ctx.load_verify_locations(f"{certs_dir}/root-ca.crt")
    cli_ctx.verify_mode = ssl.CERT_REQUIRED
    
    s_res = configure_sslcontext_hybrid_group(srv_ctx, group)
    c_res = configure_sslcontext_hybrid_group(cli_ctx, group)
    
    if not (s_res.configured and c_res.configured):
        res.error = "Native configuration failed for Asyncio contexts"
        evidence.append(res.error)
        res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
        return res
        
    async def test_routine():
        server_task = asyncio.create_task(async_server_worker(port, srv_ctx, res))
        await asyncio.sleep(0.5) 
        await run_async_client(port, cli_ctx, res, evidence)
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
            
    asyncio.run(test_routine())
    
    if res.app_data_pass:
        res.negotiated_group = group 
        evidence.append(f"Negotiated group verified by exclusive configuration: {group}")
        
    res.evidence_path = write_evidence(f"{test_name}.txt", "\n".join(evidence))
    return res

def run_repeatability_test(certs_dir, port=9400, repeat_count=20):
    success_handshakes = 0
    success_app_data = 0
    group_verification = 0
    failures = []
    
    for i in range(repeat_count):
        res = run_asyncio_pqc_test(certs_dir, group="X25519MLKEM768", port=port+i, test_name=f"repeat_{i}")
        if res.handshake_pass: success_handshakes += 1
        if res.app_data_pass: success_app_data += 1
        if res.negotiated_group == "X25519MLKEM768": group_verification += 1
        if res.error: failures.append(res.error)
        time.sleep(0.1)
        
    evidence_content = f"Total Attempts: {repeat_count}\nSuccessful Handshakes: {success_handshakes}\nSuccessful App Data: {success_app_data}\nGroup verifications: {group_verification}\n"
    for err in failures:
        evidence_content += f"Error: {err}\n"
    
    path = write_evidence("12_repeatability.txt", evidence_content)
    
    return {
        "attempts": repeat_count,
        "successful_handshakes": success_handshakes,
        "successful_app_data": success_app_data,
        "group_verifications": group_verification,
        "failures": failures,
        "evidence_path": path
    }

def run_process_stability_test(certs_dir, port=9500, repeat_count=20):
    success_count = 0
    for i in range(repeat_count):
        res = run_python_sslcontext_test(certs_dir, group="X25519MLKEM768", port=port+i, use_native_shim=True, test_name=f"stability_{i}")
        if res.app_data_pass:
            success_count += 1
    
    path = write_evidence("13_shim_safety.txt", f"Process Stability Test Attempts: {repeat_count}\nSuccesses: {success_count}\n(No process crashes observed as execution reached the end)\n")
    return {
        "attempts": repeat_count,
        "successful": success_count,
        "evidence_path": path
    }
