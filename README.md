# TLS 1.3 Protocol Simulator

This interactive TLS 1.3 simulator was developed as part of my bachelor's final thesis at the Faculty of Electrical Engineering and Computing (FER), University of Zagreb.  
It provides a step-by-step visual representation of the TLS 1.3 handshake, including message flow, encryption stages, and derived secrets, implemented with a graphical user interface using Python and Tkinter.


## Features

- Full TLS 1.3 handshake:
  - `ClientHello`
  - `ServerHello`
  - `EncryptedExtensions`
  - `Certificate`
  - `CertificateVerify`
  - `Finished` (server + client)
  - Application Data exchange
- Color-coded data:
  - 🔴 Red: Unencrypted
  - 🟢 Green: Encrypted
- Flow diagram showing the direction of each message
- Popups to explain negotiated parameters and transition to encrypted communication
- Support for a predefined cipher suite (`TLS_AES_128_GCM_SHA256`) and key group (`x25519`)
- Decryption of all encrypted messages displayed in the GUI

## Technologies Used

- Python 3
- Tkinter
- `cryptography` library

## Requirements

- Python 3.9+
- `cryptography` library

Install with:  
```pip install cryptography```


## How to run
```python main.py```


