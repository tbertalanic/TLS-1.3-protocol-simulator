from tkinter import *
from tkinter import scrolledtext, Toplevel, Checkbutton, IntVar
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

root = Tk()
root.title("TLS 1.3 simulator")
root.iconbitmap("icon.ico")

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

selected_client_cipher_suites = {k: IntVar(value=1 if k == "TLS_AES_128_GCM_SHA256" else 0) for k in CIPHER_SUITES}
selected_server_cipher_suites = {k: IntVar(value=1 if k == "TLS_AES_128_GCM_SHA256" else 0) for k in CIPHER_SUITES}
selected_signature_algorithms = {k: IntVar(value=1) for k in SIGNATURE_ALGORITHMS}
selected_supported_groups = {k: IntVar(value=1) for k in SUPPORTED_GROUPS}

def show_options(title, options_dict):
    win = Toplevel(root)
    win.title(title)
    for i, (k, var) in enumerate(options_dict.items()):
        Checkbutton(win, text=k, variable=var).grid(row=i, column=0, sticky='w')

def build_extensions_client(public_bytes):
    supported_versions = b"\x00\x2b" + b"\x00\x02" + b"\x02\x03\x04"
    sig_list = b"".join([SIGNATURE_ALGORITHMS[k] for k, v in selected_signature_algorithms.items() if v.get()])
    sig_algs = b"\x00\x0d" + len(sig_list).to_bytes(2, 'big') + len(sig_list).to_bytes(2, 'big') + sig_list
    groups_list = b"".join([SUPPORTED_GROUPS[k] for k, v in selected_supported_groups.items() if v.get()])
    groups = b"\x00\x0a" + len(groups_list).to_bytes(2, 'big') + len(groups_list).to_bytes(2, 'big') + groups_list
    key_share_entry = SUPPORTED_GROUPS["x25519"] + len(public_bytes).to_bytes(2, 'big') + public_bytes
    key_share = b"\x00\x33" + (len(key_share_entry) + 2).to_bytes(2, 'big') + len(key_share_entry).to_bytes(2, 'big') + key_share_entry
    return supported_versions + sig_algs + groups + key_share

def build_extensions_server(public_bytes):
    supported_versions = b"\x00\x2b" + b"\x00\x02" + b"\x02\x03\x04"
    key_share_entry = SUPPORTED_GROUPS["x25519"] + len(public_bytes).to_bytes(2, 'big') + public_bytes
    key_share = b"\x00\x33" + (len(key_share_entry) + 2).to_bytes(2, 'big') + len(key_share_entry).to_bytes(2, 'big') + key_share_entry
    return supported_versions + key_share

def build_client_hello():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    global client_public_key
    client_public_key = public_bytes
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    global client_session_id
    client_session_id = session_id
    cipher_suite_bytes = b"".join([v for k, v in CIPHER_SUITES.items() if selected_client_cipher_suites[k].get()])
    global client_hello_data
    client_hello_data = cipher_suite_bytes
    compression_methods = b"\x00"
    extensions = build_extensions_client(public_bytes)
    body = (
        VERSION +
        random_bytes +
        bytes([len(session_id)]) + session_id +
        len(cipher_suite_bytes).to_bytes(2, 'big') + cipher_suite_bytes +
        bytes([len(compression_methods)]) + compression_methods +
        len(extensions).to_bytes(2, 'big') + extensions
    )
    handshake_msg = MESSAGE_TYPE["client_hello"] + len(body).to_bytes(3, 'big') + body
    record = CONTENT_TYPE["handshake"] + VERSION + len(handshake_msg).to_bytes(2, 'big') + handshake_msg
    return record

def build_server_hello():
    selected = None
    selected_name = None
    for i in range(0, len(client_hello_data), 2):
        suite = client_hello_data[i:i+2]
        for k, v in CIPHER_SUITES.items():
            if v == suite and selected_server_cipher_suites[k].get():
                selected = suite
                selected_name = k
                break
        if selected:
            break
    if not selected:
        raise ValueError("No mutually supported cipher suite.")
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    random_bytes = os.urandom(32)
    compression_methods = b"\x00"
    extensions = build_extensions_server(public_bytes)
    body = (
        VERSION +
        random_bytes +
        bytes([len(client_session_id)]) + client_session_id +
        selected +
        bytes([len(compression_methods)]) + compression_methods +
        len(extensions).to_bytes(2, 'big') + extensions
    )
    handshake_msg = MESSAGE_TYPE["server_hello"] + len(body).to_bytes(3, 'big') + body
    record = CONTENT_TYPE["handshake"] + VERSION + len(handshake_msg).to_bytes(2, 'big') + handshake_msg
    return record, selected_name

def start_simulation():
    global step
    if step == 0:
        label_status.config(text="Client Hello")
        data = build_client_hello()
        server_textbox.insert(END, ' '.join(f'{b:02x}' for b in data) + '\n')
        button_simulate.config(text="Next step")
        step += 1
    elif step == 1:
        label_status.config(text="Server Hello")
        data, selected_name = build_server_hello()
        client_textbox.insert(END, ' '.join(f'{b:02x}' for b in data) + '\n')
        button_simulate.config(state=DISABLED)
        step += 1

        win = Toplevel(root)
        win.title("Negotiation Result")
        Label(win, text=f"Negotiated cipher suite: {selected_name}", padx=20, pady=20).pack()
        Button(win, text="OK", command=win.destroy).pack(pady=5)

step = 0
frame = Frame(root)
frame.pack(padx=10, pady=10)
left_frame = Frame(frame)
left_frame.grid(row=0, column=0, padx=10)
right_frame = Frame(frame)
right_frame.grid(row=0, column=1, padx=10)
Label(left_frame, text="Client").pack()
client_textbox = scrolledtext.ScrolledText(left_frame, width=60, height=20)
client_textbox.pack()
Button(left_frame, text="Cipher Suites", command=lambda: show_options("Client Cipher Suites", selected_client_cipher_suites)).pack()
Button(left_frame, text="Supported Groups", command=lambda: show_options("Client Supported Groups", selected_supported_groups)).pack()
Button(left_frame, text="Signature Algorithms", command=lambda: show_options("Client Signature Algorithms", selected_signature_algorithms)).pack()
Label(right_frame, text="Server").pack()
server_textbox = scrolledtext.ScrolledText(right_frame, width=60, height=20)
server_textbox.pack()
Button(right_frame, text="Cipher Suites", command=lambda: show_options("Server Cipher Suites", selected_server_cipher_suites)).pack()
Button(right_frame, text="Supported Groups", command=lambda: show_options("Server Supported Groups", selected_supported_groups)).pack()
Button(right_frame, text="Signature Algorithms", command=lambda: show_options("Server Signature Algorithms", selected_signature_algorithms)).pack()
bottom_frame = Frame(root)
bottom_frame.pack(pady=10)
button_simulate = Button(bottom_frame, text="Start simulation", command=start_simulation)
button_simulate.pack(side=LEFT, padx=5)
label_status = Label(bottom_frame, text="Waiting...")
label_status.pack(side=LEFT, padx=5)
root.mainloop()
