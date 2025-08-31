from tkinter import *
from tkinter import scrolledtext
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from constants import CONTENT_TYPE, VERSION
from context import TLSContext
from messages import build_client_hello, build_server_hello, build_encrypted_extensions, build_certificate, build_certificate_verify, build_finished
from ui_utils import show_popup, show_cipher_suites_info, show_signature_algorithms_info, show_supported_groups_info, append_hex, append_text
from crypto_utils import derive_shared_key, decrypt_handshake_record, derive_application_traffic_keys

tls = TLSContext()

root = Tk()
root.title("TLS 1.3 simulator")
root.iconbitmap("icon.ico")
root.state('zoomed') 
root.minsize(800, 600)
root.configure(bg="black")    
root.rowconfigure(0, weight=0)  
root.rowconfigure(1, weight=0)  
root.columnconfigure(0, weight=1)

def send_application_data():
    if tls.application_data_step % 2 == 0:
        plaintext = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        record_header = CONTENT_TYPE["application_data"] + VERSION + len(plaintext).to_bytes(2, "big")

        nonce = bytes(a ^ b for a, b in zip(tls.client_write_iv, tls.client_send_seq.to_bytes(12, 'big')))
        aead_encrypt = AESGCM(tls.client_write_key)
        aead_encrypted = aead_encrypt.encrypt(nonce, plaintext, record_header) #nonce, data to encrypt, data that sould be authenticated with the key but does not need to be encrypted
        full_record = record_header + aead_encrypted
        
        recv_nonce = bytes(a ^ b for a, b in zip(tls.client_write_iv, tls.client_send_seq.to_bytes(12, "big")))
        decrypted = AESGCM(tls.client_write_key).decrypt(recv_nonce, aead_encrypted, record_header)
        tls.client_send_seq += 1
        tls.server_recv_seq += 1

        append_hex(server_textbox, full_record, label="Received: ApplicationData", tag="encrypted")
        append_hex(client_textbox, full_record, label="Sent: ApplicationData", tag="encrypted")
        append_text(server_decrypted_textbox, decrypted.decode(), label="Decrypted ApplicationData")
    else:
        plaintext = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
        record_header = CONTENT_TYPE["application_data"] + VERSION + len(plaintext).to_bytes(2, "big")
        
        nonce = bytes(a ^ b for a, b in zip(tls.server_write_iv, tls.server_recv_seq.to_bytes(12, 'big')))
        aead_encrypt = AESGCM(tls.server_write_key)
        aead_encrypted = aead_encrypt.encrypt(nonce, plaintext, record_header)
        full_record = record_header + aead_encrypted
        
        recv_nonce = bytes(a ^ b for a, b in zip(tls.server_write_iv, tls.server_recv_seq.to_bytes(12, 'big')))
        decrypted = AESGCM(tls.server_write_key).decrypt(recv_nonce, aead_encrypted, record_header)
        tls.server_recv_seq += 1
        tls.client_recv_seq += 1
        
        append_hex(client_textbox, full_record, label="Received: ApplicationData", tag="encrypted")
        append_hex(server_textbox, full_record, label="Sent: ApplicationData", tag="encrypted")
        append_text(client_decrypted_textbox, decrypted.decode(), label="Decrypted ApplicationData")
    
    tls.application_data_step += 1

def reset_simulation():
    tls.handshake_messages = []
    tls.handshake_secret = b""
    tls.server_send_seq = 0
    tls.client_recv_seq = 0
    tls.client_send_seq = 0
    tls.server_recv_seq = 0
    tls.application_data_step = 0
    tls.step = 0

    client_textbox.delete('1.0', END)
    client_decrypted_textbox.delete('1.0', END)
    server_textbox.delete('1.0', END)
    server_decrypted_textbox.delete('1.0', END)
    flow_canvas.delete("all")
    label_status.config(text="Waiting...", fg="white")
    explanation_label.config(text="Explanation will appear here.", fg="white")
    button_simulate.config(text="Start simulation")

def update_flow_diagram(step):
    messages = [
        ("ClientHello", "right"),
        ("ServerHello", "left"),
        ("EncryptedExtensions", "left"),
        ("Certificate", "left"),
        ("CertificateVerify", "left"),
        ("ServerFinished", "left"),
        ("ClientFinished", "right"),
        ("Application Data", "center")
    ]

    if step < len(messages):
        label, direction = messages[step]
        y = 40 + step * 50
        text_y = y - 10
        flow_canvas.create_text(100, text_y, text=label, fill="white", font=("Helvetica", 12, "bold"))

        if direction == "right":
            flow_canvas.create_line(20, y, 180, y, arrow=LAST, fill="deepskyblue", width=2)
        elif direction == "left":
            flow_canvas.create_line(180, y, 20, y, arrow=LAST, fill="yellow", width=2)
        elif direction == "center":
            flow_canvas.create_line(180, y, 20, y, arrow=BOTH, fill="lime", width=2)


def start_simulation():
    if tls.step == 0:
        label_status.config(text="ClientHello")
        explanation_label.config(text="The client sends a ClientHello message to initiate the handshake, proposing supported cipher suites and key exchange groups.")
        
        data = build_client_hello(tls)
        
        append_hex(server_textbox, data, label="Received: ClientHello",  tag="unencrypted")
        append_hex(client_textbox, data, label="Sent: ClientHello",  tag="unencrypted")
        
        button_simulate.config(text="Next step")
        tls.step += 1
        update_flow_diagram(tls.step - 1)

    elif tls.step == 1:
        label_status.config(text="ServerHello")
        explanation_label.config(text="The server responds with ServerHello, choosing a cipher suite and providing its public key for key exchange.")
        
        data, selected_name = build_server_hello(tls)
        derive_shared_key(tls)
        
        append_hex(client_textbox, data, label="Received: ServerHello",  tag="unencrypted")
        append_hex(server_textbox, data, label="Sent: ServerHello",  tag="unencrypted")
    
        button_simulate.config(text="Next step")
        tls.step += 1
        update_flow_diagram(tls.step - 1)
        show_popup(
            root,
            "Negotiation Result",
            f"Negotiated cipher suite: {selected_name}"
        )

    elif tls.step == 2:
        label_status.config(text="EncryptedExtensions", fg="lime")
        explanation_label.config(text="The server sends EncryptedExtensions in an encrypted record, containing settings like the negotiated protocol version", fg="lime")
        
        data = build_encrypted_extensions(tls)
        
        append_hex(client_textbox, data, label="Received: EncryptedExtensions",  tag="encrypted")
        append_hex(server_textbox, data, label="Sent: EncryptedExtensions",  tag="encrypted")
        append_hex(client_decrypted_textbox, decrypt_handshake_record(tls, data, tls.client_recv_seq, b"s hs traffic"), label="Decrypted EncryptedExtensions")
        tls.client_recv_seq += 1
        
        button_simulate.config(text="Next step")
        tls.step += 1
        update_flow_diagram(tls.step - 1)
        show_popup(
            root,
            "Handshake Encryption Enabled",
            "From this point onward, all handshake messages are encrypted using traffic keys derived from the shared secret established via ECDHE."
        )

    elif tls.step == 3:
        label_status.config(text="Certificate", fg="lime")
        explanation_label.config(text="The server sends its certificate to prove its identity using a public key associated with the domain.", fg="lime")
        
        data = build_certificate(tls)
        
        append_hex(client_textbox, data, label="Received: Certificate",  tag="encrypted")
        append_hex(server_textbox, data, label="Sent: Certificate",  tag="encrypted")
        append_hex(client_decrypted_textbox, decrypt_handshake_record(tls, data, tls.client_recv_seq, b"s hs traffic"), label="Decrypted Certificate")
        tls.client_recv_seq += 1
        
        button_simulate.config(text="Next step")
        tls.step += 1
        update_flow_diagram(tls.step - 1)

    elif tls.step == 4:
        label_status.config(text="CertificateVerify", fg="lime")
        explanation_label.config(text="The server sends CertificateVerify, signing the handshake to prove it holds the private key corresponding to its certificate.", fg="lime")
        
        data = build_certificate_verify(tls)
        
        append_hex(client_textbox, data, label="Received: CertificateVerify", tag="encrypted")
        append_hex(server_textbox, data, label="Sent: CertificateVerify", tag="encrypted")
        append_hex(client_decrypted_textbox, decrypt_handshake_record(tls, data, tls.client_recv_seq, b"s hs traffic"), label="Decrypted CertificateVerify")
        tls.client_recv_seq += 1
        
        button_simulate.config(text="Next step")
        tls.step += 1
        update_flow_diagram(tls.step - 1)

    elif tls.step == 5:
        label_status.config(text="ServerFinished", fg="lime")
        explanation_label.config(text="The server sends a Finished message, which contains a MAC of the entire handshake. This proves all previous handshake messages were received unmodified.", fg="lime")
        
        data = build_finished(tls, b"server finished")
        
        append_hex(client_textbox, data, label="Received: ServerFinished", tag="encrypted")
        append_hex(server_textbox, data, label="Sent: ServerFinished", tag="encrypted")
        append_hex(client_decrypted_textbox, decrypt_handshake_record(tls, data, tls.client_recv_seq, b"s hs traffic"), label="Decrypted ServerFinished")
        tls.client_recv_seq += 1
        
        button_simulate.config(text="Next step")
        tls.step += 1
        update_flow_diagram(tls.step - 1)

    elif tls.step == 6:
        label_status.config(text="ClientFinished", fg="lime")
        explanation_label.config(text="The client sends its Finished message. If valid, the handshake is confirmed secure and encrypted communication can begin.", fg="lime")
        
        data = build_finished(tls, b"client finished")
        
        append_hex(server_textbox, data, label="Received: ClientFinished", tag="encrypted")
        append_hex(client_textbox, data, label="Sent: ClientFinished", tag="encrypted")
        append_hex(server_decrypted_textbox, decrypt_handshake_record(tls, data, tls.server_recv_seq, b"c hs traffic"), label="Decrypted ClientFinished")
        
        button_simulate.config(text="Next step")
        tls.step += 1
        update_flow_diagram(tls.step - 1)
        show_popup(
            root,
            "Handshake complete",
            "The handshake is complete. The client and server now derive new keys from the master secret to encrypt all application data."
        )

    elif tls.step == 7:
        label_status.config(text="Application data", fg="lime")
        explanation_label.config(text="The secure channel is established. Both client and server now exchange encrypted application data.", fg="lime")
        
        derive_application_traffic_keys(tls)
        send_application_data()
        
        button_simulate.config(text="Next step")
        tls.step += 1
        update_flow_diagram(tls.step - 1)
        
    else:
        label_status.config(text="Application data")
        send_application_data()

frame = Frame(root, bg="black")
frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=0)
frame.columnconfigure(2, weight=1)
frame.rowconfigure(0, weight=1)

left_frame = Frame(frame, bg="black", width=600, height=500)
left_frame.grid(row=0, column=0, padx=10, sticky="nsew")
left_frame.columnconfigure(0, weight=1)
left_frame.rowconfigure(1, weight=1)
left_frame.pack_propagate(False)

Label(left_frame, text="Client", font=("Helvetica", 16, "bold"), bg="black", fg="white").pack()
client_textbox = scrolledtext.ScrolledText(left_frame, width=80, height=8, font=("Helvetica", 12), bg="black", fg="white")
client_textbox.tag_config("encrypted", foreground="lime")
client_textbox.tag_config("unencrypted", foreground="red")
client_textbox.pack(expand=True, fill=BOTH)

Label(left_frame, text="Client - Decrypted Received Data", font=("Helvetica", 16), bg="black", fg="white").pack()
client_decrypted_textbox = scrolledtext.ScrolledText(left_frame, width=80, height=8, font=("Helvetica", 12), bg="black", fg="white")
client_decrypted_textbox.tag_config("encrypted", foreground="lime")
client_decrypted_textbox.tag_config("unencrypted", foreground="red")
client_decrypted_textbox.pack(expand=True, fill=BOTH)

button_row_left = Frame(left_frame, bg="black")
button_row_left.pack(pady=5)
Button(button_row_left, text="Cipher Suites", font=("Helvetica", 12), command=lambda: show_cipher_suites_info(root)).grid(row=0, column=0, padx=5)
Button(button_row_left, text="Supported Groups", font=("Helvetica", 12), command=lambda: show_supported_groups_info(root)).grid(row=0, column=1, padx=5)
Button(button_row_left, text="Signature Algorithms", font=("Helvetica", 12), command=lambda: show_signature_algorithms_info(root)).grid(row=0, column=2, padx=5)

right_frame = Frame(frame, bg="black", width=600, height=500)
right_frame.grid(row=0, column=2, padx=10, sticky="nsew")
right_frame.columnconfigure(0, weight=1)
right_frame.rowconfigure(1, weight=1)
right_frame.pack_propagate(False)

Label(right_frame, text="Server", font=("Helvetica", 16, "bold"), bg="black", fg="white").pack()
server_textbox = scrolledtext.ScrolledText(right_frame, width=80, height=8, font=("Helvetica", 12), bg="black", fg="white")
server_textbox.tag_config("encrypted", foreground="lime")
server_textbox.tag_config("unencrypted", foreground="red")
server_textbox.pack(expand=True, fill=BOTH)

Label(right_frame, text="Server - Decrypted Received Data", font=("Helvetica", 16), bg="black", fg="white").pack()
server_decrypted_textbox = scrolledtext.ScrolledText(right_frame, width=80, height=8, font=("Helvetica", 12), bg="black", fg="white")
server_decrypted_textbox.tag_config("encrypted", foreground="lime")
server_decrypted_textbox.tag_config("unencrypted", foreground="red")
server_decrypted_textbox.pack(expand=True, fill=BOTH)

button_row_right = Frame(right_frame, bg="black")
button_row_right.pack(pady=5)
Button(button_row_right, text="Cipher Suites", font=("Helvetica", 12), command=lambda: show_cipher_suites_info(root)).grid(row=0, column=0, padx=5)
Button(button_row_right, text="Supported Groups", font=("Helvetica", 12), command=lambda: show_supported_groups_info(root)).grid(row=0, column=1, padx=5)
Button(button_row_right, text="Signature Algorithms", font=("Helvetica", 12), command=lambda: show_signature_algorithms_info(root)).grid(row=0, column=2, padx=5)

flow_frame = Frame(frame, bg="black", width=200, height=500)
flow_frame.grid(row=0, column=1, padx=10, sticky="nsew")
flow_canvas = Canvas(flow_frame, width=200, bg="black", highlightthickness=0)
flow_canvas.pack(expand=True, fill=BOTH)

bottom_frame = Frame(root, height=160, bg="black")
bottom_frame.grid(row=1, column=0, sticky="ew", pady=(10, 20))
bottom_frame.grid_propagate(False)
bottom_frame.columnconfigure(0, weight=1)

inner_col = Frame(bottom_frame, bg="black")
inner_col.pack(expand=True)

button_row_controls = Frame(inner_col, bg="black")
button_row_controls.pack(pady=(5, 10))

button_simulate = Button(button_row_controls, text="Start simulation", font=("Helvetica", 16, "bold"), command=start_simulation)
button_simulate.grid(row=0, column=0, padx=10)

button_reset = Button(button_row_controls, text="Reset simulation", font=("Helvetica", 16), command=reset_simulation)
button_reset.grid(row=0, column=1, padx=10)

info_box = LabelFrame(inner_col, text="Current Step", font=("Helvetica", 12, "bold"), fg="white", bg="black", bd=2, relief=RIDGE, labelanchor="n")
info_box.pack(padx=20, fill=X)

label_status = Label(info_box, text="Waiting...", font=("Helvetica", 19, "bold"), fg="white", bg="black", anchor="center")
label_status.pack(pady=(10, 5))

explanation_label = Label(info_box, text="Explanation will appear here.", font=("Helvetica", 16), fg="white", bg="black", wraplength=1000, justify=CENTER)
explanation_label.pack(pady=(0, 10))

legend_frame = Frame(root, bg="black")
legend_frame.place(relx=1.0, rely=1.0, anchor="se", x=-20, y=-10)

Label(legend_frame, text="Unencrypted data shown in red", font=("Helvetica", 13), fg="red", bg="black").pack(anchor="w")
Label(legend_frame, text="Encrypted data shown in green", font=("Helvetica", 13), fg="lime", bg="black").pack(anchor="w")

root.mainloop()
