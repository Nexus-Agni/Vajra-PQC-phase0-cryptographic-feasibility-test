import ctypes
import socket
import ssl

class OpenSSLGroups:
    def __init__(self):
        try:
            self.libssl = ctypes.CDLL("libssl.so.3")
            # SSL_CTX_new
            self.libssl.SSL_CTX_new.argtypes = [ctypes.c_void_p]
            self.libssl.SSL_CTX_new.restype = ctypes.c_void_p
            # TLS_method
            self.libssl.TLS_method.argtypes = []
            self.libssl.TLS_method.restype = ctypes.c_void_p
            # SSL_CTX_ctrl
            self.libssl.SSL_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
            self.libssl.SSL_CTX_ctrl.restype = ctypes.c_long
            # OPENSSL_init_ssl
            try:
                self.libssl.OPENSSL_init_ssl.argtypes = [ctypes.c_uint64, ctypes.c_void_p]
                self.libssl.OPENSSL_init_ssl.restype = ctypes.c_int
                # OPENSSL_INIT_LOAD_CONFIG = 0x00000040
                self.libssl.OPENSSL_init_ssl(0x00000040, None)
            except Exception:
                pass
            # SSL_new
            self.libssl.SSL_new.argtypes = [ctypes.c_void_p]
            self.libssl.SSL_new.restype = ctypes.c_void_p
            # SSL_set_fd
            self.libssl.SSL_set_fd.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.libssl.SSL_set_fd.restype = ctypes.c_int
            # SSL_connect
            self.libssl.SSL_connect.argtypes = [ctypes.c_void_p]
            self.libssl.SSL_connect.restype = ctypes.c_int
            # SSL_accept
            self.libssl.SSL_accept.argtypes = [ctypes.c_void_p]
            self.libssl.SSL_accept.restype = ctypes.c_int
            # SSL_get_verify_result
            self.libssl.SSL_get_verify_result.argtypes = [ctypes.c_void_p]
            self.libssl.SSL_get_verify_result.restype = ctypes.c_long
            # SSL_get_error
            self.libssl.SSL_get_error.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.libssl.SSL_get_error.restype = ctypes.c_int
            # SSL_free
            self.libssl.SSL_free.argtypes = [ctypes.c_void_p]
            self.libssl.SSL_free.restype = None
            # SSL_get0_group_name
            self.libssl.SSL_get0_group_name.argtypes = [ctypes.c_void_p]
            self.libssl.SSL_get0_group_name.restype = ctypes.c_char_p
            # ERR_get_error
            try:
                self.libcrypto = ctypes.CDLL("libcrypto.so.3")
                self.libcrypto.ERR_get_error.argtypes = []
                self.libcrypto.ERR_get_error.restype = ctypes.c_ulong
                self.libcrypto.ERR_error_string.argtypes = [ctypes.c_ulong, ctypes.c_char_p]
                self.libcrypto.ERR_error_string.restype = ctypes.c_char_p
                self.libssl.ERR_get_error = self.libcrypto.ERR_get_error
                self.libssl.ERR_error_string = self.libcrypto.ERR_error_string
            except Exception:
                pass
            # SSL_CTX_use_certificate_chain_file
            self.libssl.SSL_CTX_use_certificate_chain_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self.libssl.SSL_CTX_use_certificate_chain_file.restype = ctypes.c_int
            # SSL_CTX_use_PrivateKey_file
            self.libssl.SSL_CTX_use_PrivateKey_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
            self.libssl.SSL_CTX_use_PrivateKey_file.restype = ctypes.c_int
            # SSL_CTX_load_verify_locations
            self.libssl.SSL_CTX_load_verify_locations.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
            self.libssl.SSL_CTX_load_verify_locations.restype = ctypes.c_int
            # SSL_CTX_set_verify
            self.libssl.SSL_CTX_set_verify.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
            self.libssl.SSL_CTX_set_verify.restype = None
            
            # SSL_write, SSL_read
            self.libssl.SSL_write.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
            self.libssl.SSL_write.restype = ctypes.c_int
            self.libssl.SSL_read.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
            self.libssl.SSL_read.restype = ctypes.c_int
            
            self.SSL_FILETYPE_PEM = 1
            self.SSL_VERIFY_PEER = 1
            self.SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2
            
            self.loaded = True
        except Exception as e:
            self.loaded = False
            self.error = str(e)

    def create_context(self, is_server=False, certfile=None, keyfile=None, cafile=None, groups=None):
        if not self.loaded: return None
        method = self.libssl.TLS_method()
        ctx = self.libssl.SSL_CTX_new(method)
        if groups:
            # SSL_CTRL_SET_GROUPS_LIST = 92
            self.libssl.SSL_CTX_ctrl(ctx, 92, 0, groups.encode())
        if certfile and keyfile:
            ret1 = self.libssl.SSL_CTX_use_certificate_chain_file(ctx, certfile.encode())
            ret2 = self.libssl.SSL_CTX_use_PrivateKey_file(ctx, keyfile.encode(), self.SSL_FILETYPE_PEM)
            if ret1 != 1 or ret2 != 1:
                self.error = f"Failed to load cert ({ret1}) or key ({ret2})"
                self.loaded = False
        if cafile:
            ret = self.libssl.SSL_CTX_load_verify_locations(ctx, cafile.encode(), None)
            if ret != 1:
                self.error = "Failed to load CA file"
                self.loaded = False
            verify_mode = self.SSL_VERIFY_PEER
            if is_server:
                verify_mode |= self.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            self.libssl.SSL_CTX_set_verify(ctx, verify_mode, None)
        return ctx

    def get_group_name(self, ssl_ptr):
        if not self.loaded: return None
        ptr = self.libssl.SSL_get0_group_name(ssl_ptr)
        if ptr:
            return ctypes.string_at(ptr).decode()
        return None
