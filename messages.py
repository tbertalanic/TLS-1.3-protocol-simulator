import os, hashlib
from cryptography.hazmat.primitives.asymmetric import x25519, padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from constants import CIPHER_SUITES, SIGNATURE_ALGORITHMS, SUPPORTED_GROUPS, CONTENT_TYPE, VERSION, MESSAGE_TYPE
from context import TLSContext
from crypto_utils import hkdf_expand, encrypt_handshake_record

def build_extensions_client(public_bytes):
    versions = b"\x03\x04"
    versions_len = len(versions).to_bytes(1, "big")
    supported_versions_data = versions_len + versions
    supported_versions = b"\x00\x2b" + len(supported_versions_data).to_bytes(2, "big") + supported_versions_data
    
    sig_alg = SIGNATURE_ALGORITHMS["rsa_pss_rsae_sha256"]
    sigalgs_len = len(sig_alg).to_bytes(2, "big")
    sig_algs_data = sigalgs_len + sig_alg
    sig_algs = b"\x00\x0d" + len(sig_algs_data).to_bytes(2, "big") + sig_algs_data
    
    group = SUPPORTED_GROUPS["x25519"]
    groups_data = len(group).to_bytes(2, "big") + group
    groups = b"\x00\x0a" + len(groups_data).to_bytes(2, "big") + groups_data
    
    key_exchange = len(public_bytes).to_bytes(2, "big") + public_bytes
    key_share_entry = SUPPORTED_GROUPS["x25519"] + key_exchange
    key_share_data = len(key_share_entry).to_bytes(2, "big") + key_share_entry
    key_share = b"\x00\x33" + len(key_share_data).to_bytes(2, "big") + key_share_data
    
    return supported_versions + sig_algs + groups + key_share

def build_extensions_server(public_bytes):
    supported_versions_data = b"\x03\x04"
    supported_versions = b"\x00\x2b" + len(supported_versions_data).to_bytes(2, "big") + supported_versions_data
    
    key_exchange = len(public_bytes).to_bytes(2, "big") + public_bytes
    key_share_entry = SUPPORTED_GROUPS["x25519"] + key_exchange
    key_share = b"\x00\x33" + len(key_share_entry).to_bytes(2, "big") + key_share_entry
    
    return supported_versions + key_share

def build_client_hello(tls: TLSContext):
    tls.client_private_key = x25519.X25519PrivateKey.generate()
    public_key = tls.client_private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    tls.client_public_key = public_bytes
    
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    tls.client_session_id = session_id
    
    cipher_suite_bytes = CIPHER_SUITES["TLS_AES_128_GCM_SHA256"]
    compression_methods = b"\x00"
    
    extensions = build_extensions_client(public_bytes)
    body = (
        VERSION +
        random_bytes +
        session_id +
        cipher_suite_bytes +
        compression_methods +
        extensions
    )
    
    handshake_msg = MESSAGE_TYPE["client_hello"] + len(body).to_bytes(3, 'big') + body
    record = CONTENT_TYPE["handshake"] + VERSION + len(handshake_msg).to_bytes(2, 'big') + handshake_msg
    tls.handshake_messages.append(handshake_msg)
    
    return record

def build_server_hello(tls: TLSContext):
    selected = CIPHER_SUITES["TLS_AES_128_GCM_SHA256"]
    selected_name = "TLS_AES_128_GCM_SHA256"
    
    tls.server_private_key = x25519.X25519PrivateKey.generate()
    public_key = tls.server_private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    tls.server_public_key = public_bytes
    
    random_bytes = os.urandom(32)
    compression_methods = b"\x00"
    
    extensions = build_extensions_server(public_bytes)
    body = (
        VERSION +
        random_bytes +
        tls.client_session_id +
        selected +
        compression_methods +
        extensions
    )
    
    handshake_msg = MESSAGE_TYPE["server_hello"] + len(body).to_bytes(3, 'big') + body
    record = CONTENT_TYPE["handshake"] + VERSION + len(handshake_msg).to_bytes(2, 'big') + handshake_msg
    tls.handshake_messages.append(handshake_msg)
    
    return record, selected_name

def build_encrypted_extensions(tls: TLSContext):
    supported_versions_data = b"\x03\x04"
    supported_versions = b"\x00\x2b" + len(supported_versions_data).to_bytes(2, "big") + supported_versions_data
    body = len(supported_versions).to_bytes(2, 'big') + supported_versions
    plaintext = MESSAGE_TYPE["encrypted_extensions"] + body + supported_versions
    return encrypt_handshake_record(tls, plaintext, sender="server", label=b"s hs traffic")

def build_certificate(tls: TLSContext):
    dummy_cert = os.urandom(128)
    plaintext = MESSAGE_TYPE["certificate"] + dummy_cert
    return encrypt_handshake_record(tls, plaintext, sender="server", label=b"s hs traffic") #client will extract the public key from the sent certificate

def build_certificate_verify(tls: TLSContext):
    transcript_hash = hashlib.sha256(b"".join(tls.handshake_messages)).digest()
    context = b"TLS 1.3, server CertificateVerify"
    to_sign = b"\x20" * 64 + context + b"\x00" + transcript_hash
    signing_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    signature = signing_private_key.sign(
        to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature_algorithm = SIGNATURE_ALGORITHMS["rsa_pss_rsae_sha256"]
    body = signature_algorithm + len(signature).to_bytes(2, 'big') + signature
    plaintext = MESSAGE_TYPE["certificate_verify"] + len(body).to_bytes(3, 'big') + body
    return encrypt_handshake_record(tls, plaintext, sender="server", label=b"s hs traffic")

def build_finished(tls: TLSContext, label):
    finished_key = hkdf_expand(tls.handshake_secret, b"finished", 32)
    transcript_hash = hashlib.sha256(b"".join(tls.handshake_messages)).digest()
    h = hmac.HMAC(finished_key, hashes.SHA256(), backend=default_backend()) #key, hash algorithm
    h.update(transcript_hash)  #hash and authenticate
    verify_data = h.finalize() #finalize context so update and other functions can't be called anymore
    
    plaintext = MESSAGE_TYPE["finished"] + verify_data
    if label == b"client finished":
        return encrypt_handshake_record(tls, plaintext, sender="client", label=b"c hs traffic")
    elif label ==b"server finished":
        return encrypt_handshake_record(tls, plaintext, sender="server", label=b"s hs traffic") 
    