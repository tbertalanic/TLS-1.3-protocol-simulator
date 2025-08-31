CONTENT_TYPE = {
    "change_cipher_spec" : b"\x14",
    "alert" : b"\x15",
    "handshake" : b"\x16",
    "application_data" : b"\x17",
    "heartbeat" : b"\x18"
}

VERSION = b"\x03\x03"

MESSAGE_TYPE = {
    "client_hello" : b"\x01",
    "server_hello" : b"\x02",
    "encrypted_extensions" : b"\x08",
    "certificate" : b"\x0b",
    "certificate_request" : b"\x0d",
    "certificate_verify" : b"\x0f",
    "finished" : b"\x14"
}

#list of cipher suites which indicates the AEAD algorithm/HKDF hash pairs supported
CIPHER_SUITES = {
    "TLS_AES_128_GCM_SHA256" : b"\x13\x01",
    "TLS_AES_256_GCM_SHA384" : b"\x13\x02",
    "TLS_CHACHA20_POLY1305_SHA256" : b"\x13\x03",
    "TLS_AES_128_CCM_SHA256" : b"\x13\x04",
    "TLS_AES_128_CCM_8_SHA256" : b"\x13\x05"
}

LEGACY_COMPRESSION_METHODS = b"\x01\x00"

#signature_algorithm extension indicates which signature algorithms may be used in digital signatures in CertificateVerity messages
SIGNATURE_ALGORITHMS = {
    "rsa_pkcs1_sha256" : b"\x04\x01",
    "rsa_pkcs1_sha384" : b"\x05\x01",
    "rsa_pkcs1_sha512" : b"\x06\x01",
    "ecdsa_secp256r1_sha256" : b"\x04\x03",
    "ecdsa_secp384r1_sha384" : b"\x05\x03",
    "ecdsa_secp521r1_sha512" : b"\x06\x03",
    "rsa_pss_rsae_sha256" : b"\x08\x04",
    "rsa_pss_rsae_sha384" : b"\x08\x05",
    "rsa_pss_rsae_sha512" : b"\x08\x06",
    "ed25519" : b"\x08\x07",
    "ed448" : b"\x08\x08",
    "rsa_pss_pss_sha256" : b"\x08\x09",
    "rsa_pss_pss_sha384" : b"\x08\x0a",
    "rsa_pss_pss_sha512" : b"\x08\x0b"
}

#supported_groups extension indicates the groups which the client supports for key exchange
SUPPORTED_GROUPS = {
    #elliptic curve groups ECDHE
    "secp256r1" : b"\x00\x17",
    "secp384r1" : b"\x00\x18",
    "secp521r1" : b"\x00\x19",
    "x25519" : b"\x00\x1d",
    "x448" : b"\x00\x1e",
    #finite field groups DHE
    "ffdhe2048" : b"\x01\x00",
    "ffdhe3072" : b"\x01\x01",
    "ffdhe4096" : b"\x01\x02",
    "ffdhe6144" : b"\x01\x03",
    "ffdhe8192" : b"\x01\x04",
}