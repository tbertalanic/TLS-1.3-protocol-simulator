from tkinter import *
from tkinter import Toplevel
from constants import CIPHER_SUITES, SIGNATURE_ALGORITHMS, SUPPORTED_GROUPS

def center_window(window, parent):
    window.update_idletasks()
    w = window.winfo_width()
    h = window.winfo_height()
    pw = parent.winfo_width()
    ph = parent.winfo_height()
    px = parent.winfo_x()
    py = parent.winfo_y()
    x = px + (pw - w) // 2
    y = py + (ph - h) // 2
    window.geometry(f"+{x}+{y}")

def show_popup(parent, title, message):
    win = Toplevel(parent)
    win.title(title)

    Label(win, text=message, wraplength=700, font=("Helvetica", 14), justify=CENTER).pack(padx=20, pady=20)
    Button(win, text="OK", font=("Helvetica", 12), command=win.destroy).pack(pady=(0, 10))
    
    center_window(win, parent)
    win.grab_set()       
    win.focus_force()
    parent.wait_window(win) 

def show_static_info(parent, title, supported, all_options, description):
    win = Toplevel(parent)
    win.title(title)

    Label(win, text=description, wraplength=600, justify=LEFT, font=("Helvetica", 12)).pack(padx=10, pady=(10, 5))

    Label(win, text="✅ Supported:", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=10)
    for item in supported:
        Label(win, text=f"• {item}", font=("Helvetica", 12)).pack(anchor="w", padx=25)

    unsupported = [item for item in all_options if item not in supported]
    if unsupported:
        Label(win, text="\n🔸 Other Available Options:", font=("Helvetica", 12, "bold")).pack(anchor="w", padx=10)
        for item in unsupported:
            Label(win, text=f"• {item}", font=("Helvetica", 12)).pack(anchor="w", padx=25)

    Button(win, text="OK", font=("Helvetica", 12), command=win.destroy).pack(pady=10)
    
    center_window(win, parent)
    win.grab_set()       
    win.focus_force()
    parent.wait_window(win) 

def show_cipher_suites_info(parent):
    show_static_info(
        parent,
        "Cipher Suites",
        supported=["TLS_AES_128_GCM_SHA256"],
        all_options=list(CIPHER_SUITES.keys()),
        description="Cipher suites define the cryptographic algorithms used to secure the TLS session.\n\nThe selected cipher suite determines the key exchange, encryption, and MAC algorithms."
    )

def show_supported_groups_info(parent):
    show_static_info(
        parent,
        "Supported Groups",
        supported=["x25519"],
        all_options=list(SUPPORTED_GROUPS.keys()),
        description="Supported groups define the elliptic curve or finite field groups used for key exchange.\n\n"
    )

def show_signature_algorithms_info(parent):
    show_static_info(
        parent,
        "Signature Algorithms",
        supported=["rsa_pss_rsae_sha256"],
        all_options=list(SIGNATURE_ALGORITHMS.keys()),
        description="Signature algorithms are used by the server to prove ownership of its certificate and sign handshake data.\n\n"
    )

def append_hex(box, data, label="", tag=None):
    if label:
        box.insert(END, f"[{label}]\n", "bold")
    hex_data = " ".join(f"{b:02x}" for b in data)
    if tag:
        box.insert(END, hex_data + "\n\n", tag)
    else:
        box.insert(END, hex_data + "\n\n")
    box.see(END)

def append_text(box, text, label=None):
    if label:
        box.insert(END, f"[{label}]\n")
    box.insert(END, text + "\n\n")
    box.see(END)