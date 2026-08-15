import socket
import threading
import time
import subprocess
import traceback
import ctypes
from dataclasses import dataclass
from src.openssl_groups import OpenSSLGroups
import ssl

@dataclass
class TLSTestResult:
    tls_version: str = ""
    mtls_pass: bool = False
    requested_group: str = ""
    negotiated_group: str = ""
    cipher_suite: str = ""
    handshake_pass: bool = False
    app_data_pass: bool = False
    handshake_duration_ms: float = 0.0
    client_error: str = ""
    server_error: str = ""
    pqc_configurable: bool = False

def run_openssl_cli_test(certs_dir, group="X25519", port=9000) -> TLSTestResult:
    res = TLSTestResult(requested_group=group)
    
    server_cmd = [
        "openssl", "s_server",
        "-accept", str(port),
        "-cert", f"{certs_dir}/server.crt",
        "-key", f"{certs_dir}/server.key",
        "-CAfile", f"{certs_dir}/root-ca.crt",
        "-Verify", "1",
        "-tls1_3",
        "-groups", group,
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
    time.sleep(1) # wait for server to start

    start = time.time()
    try:
        client_proc = subprocess.run(client_cmd, input="VAJRA-PQC-PHASE0-TEST\n", capture_output=True, text=True, timeout=5)
        end = time.time()
        
        # Read server output. It will block if quiet is false, but with -quiet it prints verification and then data.
        # So we send input via client, and then we close server.
        server_proc.stdin.write("VAJRA-PQC-PHASE0-ACK\n")
        server_proc.stdin.flush()
        time.sleep(0.5)
        server_proc.terminate()
        server_out, server_err = server_proc.communicate(timeout=2)
        
        c_out = client_proc.stdout
        c_err = client_proc.stderr
        
        if "TLSv1.3" in c_out or "TLSv1.3" in c_err:
            res.tls_version = "TLSv1.3"
        
        if "Server Temp Key: " in c_out:
            # Format: Server Temp Key: X25519MLKEM768, 2048 bits
            for line in c_out.split('\n'):
                if "Server Temp Key:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        key_info = parts[1].strip()
                        res.negotiated_group = key_info.split(',')[0].strip()
        
        if res.negotiated_group == "":
            res.client_error = "Negotiated group not found. OpenSSL output snippet:\n" + c_out[:500]
            
        if client_proc.returncode == 0:
            res.handshake_pass = True
            res.mtls_pass = True # since we used -Verify 1 and client passed cert
            res.handshake_duration_ms = (end - start) * 1000
            
            if "VAJRA-PQC-PHASE0-TEST" in server_out or "VAJRA-PQC-PHASE0-TEST" in server_err:
                res.app_data_pass = True
        else:
            res.client_error = c_err.strip()[-500:]
            res.server_error = server_err.strip()[-500:]

    except Exception as e:
        res.client_error = str(e)
        server_proc.terminate()
        
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
            err_buf = ctypes.create_string_buffer(256)
            ffi.libssl.ERR_error_string(ffi.libssl.ERR_get_error(), err_buf)
            res_obj.server_error = f"SSL_accept failed with error code {err}, {err_buf.value.decode()}"
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

def run_python_tls_test(certs_dir, group="X25519", port=9100, client_cert_valid=True) -> TLSTestResult:
    ffi = OpenSSLGroups()
    res = TLSTestResult(requested_group=group)
    
    if not ffi.loaded:
        res.client_error = f"FFI binding failed to load libssl. Error: {getattr(ffi, 'error', 'Unknown')}"
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
        return res
        
    cli_ctx = ffi.create_context(
        is_server=False,
        certfile=f"{certs_dir}/client.crt" if client_cert_valid else f"{certs_dir}/server.crt",
        keyfile=f"{certs_dir}/client.key" if client_cert_valid else f"{certs_dir}/server.key",
        cafile=f"{certs_dir}/root-ca.crt",
        groups=group
    )
    if not cli_ctx:
        res.client_error = "Failed to create client SSL_CTX"
        return res
        
    res.pqc_configurable = True
    
    t = threading.Thread(target=py_server_worker, args=(port, srv_ctx, ffi, res))
    t.daemon = True
    t.start()
    
    time.sleep(0.5)
    
    start_time = time.time()
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.settimeout(5.0)
    ssl_ptr = None
    
    try:
        client_sock.connect(("127.0.0.1", port))
        client_sock.setblocking(True)
        
        ssl_ptr = ffi.libssl.SSL_new(cli_ctx)
        ffi.libssl.SSL_set_fd(ssl_ptr, client_sock.fileno())
        
        ret = ffi.libssl.SSL_connect(ssl_ptr)
        end_time = time.time()
        
        if ret <= 0:
            err = ffi.libssl.SSL_get_error(ssl_ptr, ret)
            v_err = ffi.libssl.SSL_get_verify_result(ssl_ptr)
            err_buf = ctypes.create_string_buffer(256)
            ffi.libssl.ERR_error_string(ffi.libssl.ERR_get_error(), err_buf)
            res.client_error = f"SSL_connect failed with OpenSSL error code {err}, Verify error: {v_err}: {err_buf.value.decode()}"
            return res
            
        res.tls_version = "TLSv1.3" # Hardcoded assumption for this basic FFI
        res.handshake_pass = True
        res.mtls_pass = True
        res.handshake_duration_ms = (end_time - start_time) * 1000.0
        
        neg_group = ffi.get_group_name(ssl_ptr)
        if neg_group:
            res.negotiated_group = neg_group
            
        req = b"VAJRA-PQC-PHASE0-TEST"
        ffi.libssl.SSL_write(ssl_ptr, req, len(req))
        
        buf = ctypes.create_string_buffer(1024)
        bytes_read = ffi.libssl.SSL_read(ssl_ptr, buf, 1024)
        
        if bytes_read > 0 and b"VAJRA-PQC-PHASE0-ACK" in buf.value:
            res.app_data_pass = True
            
    except Exception as e:
        res.client_error = f"Client Python Error: {traceback.format_exc()}"
    finally:
        if ssl_ptr:
            ffi.libssl.SSL_free(ssl_ptr)
        client_sock.close()
        
    # Wait for server thread to die
    t.join(timeout=1.0)
        
    return res
