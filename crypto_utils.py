import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from constants import CONTENT_TYPE, VERSION
from context import TLSContext

def hkdf_extract(salt, ikm): #ikm is input keying material
    h = hmac.HMAC(salt, hashes.SHA256(), backend=default_backend())
    h.update(ikm)
    return h.finalize() #pseudorandom key

def hkdf_expand(secret, label, length, context=b""):
    full_label = b"tls13 " + label
    hkdf_label = (
        length.to_bytes(2, 'big') +
        bytes([len(full_label)]) + full_label +
        bytes([len(context)]) + context
    )
    hkdf = HKDFExpand( #pseudorandom key is used to produced/expanded as much as needed
        algorithm=hashes.SHA256(),
        length=length,
        info=hkdf_label,
        backend=default_backend()
    )
    return hkdf.derive(secret)

def derive_shared_key(tls: TLSContext): #from client perspective, but both gives the same result
    #derives handshake_secret from (EC)DHE using HKDF-Extract and HKDF-Expand
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(tls.server_public_key)
    shared_secret = tls.client_private_key.exchange(peer_public_key) #performs scalar multiplication
    early_secret = hkdf_extract(b"\x00" * 32, b"\x00" * 0)
    derived_secret = hkdf_expand(early_secret, b"derived", 32)
    tls.handshake_secret = hkdf_extract(derived_secret, shared_secret) #(current secret, new secret to be added)

def derive_handshake_traffic_keys(tls: TLSContext, label: bytes):
    transcript_hash = hashlib.sha256(b"".join(tls.handshake_messages)).digest()
    handshake_traffic  = hkdf_expand(tls.handshake_secret, label, 32, transcript_hash) #server handshake traffic, context is the hash
    return hkdf_expand(handshake_traffic,b"key",32), hkdf_expand(handshake_traffic,b"iv",12)

def encrypt_handshake_record(tls: TLSContext, plaintext, sender="server", label=b"s hs traffic"):
    if sender == "server":
        seq = tls.server_send_seq
    elif sender == "client":
        seq = tls.client_send_seq

    tls.handshake_messages.append(plaintext)
    key, iv = derive_handshake_traffic_keys(tls, label) # server's handshake encryptionkey and IV derived from the shared secret along with handshake_messages so far
    nonce   = bytes(a ^ b for a,b in zip(iv, seq.to_bytes(12,"big"))) #seq is always incremented
    aead_encrypt = AESGCM(key)
    record_length = len(plaintext) + 16  # AES-GCM tag size
    record_header = CONTENT_TYPE["handshake"] + VERSION + record_length.to_bytes(2, "big")
    aead_encrypted = aead_encrypt.encrypt(nonce, plaintext, record_header)

    if sender == "server":
        tls.server_send_seq += 1
    elif sender == "client":
        tls.client_send_seq += 1
    return record_header + aead_encrypted

def decrypt_handshake_record(tls: TLSContext, record, seq, label: bytes):
    key, iv = derive_handshake_traffic_keys(tls, label)
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
    aead_decrypt = AESGCM(key)
    record_header = record[:5]
    aead_encrypted = record[5:5 + int.from_bytes(record[3:5], "big")]
    return aead_decrypt.decrypt(nonce, aead_encrypted, record_header)

def derive_application_traffic_keys(tls: TLSContext):
    client_secret = hkdf_expand(tls.handshake_secret, b"c ap traffic", 32)
    server_secret = hkdf_expand(tls.handshake_secret, b"s ap traffic", 32)
    tls.client_write_key = hkdf_expand(client_secret, b"key", 32)
    tls.client_write_iv = hkdf_expand(client_secret, b"iv", 12)
    tls.server_write_key = hkdf_expand(server_secret, b"key", 32)
    tls.server_write_iv = hkdf_expand(server_secret, b"iv", 12)
