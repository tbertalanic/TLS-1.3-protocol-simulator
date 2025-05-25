class TLSContext:
    def __init__(self):
        self.handshake_messages = []
        self.handshake_secret = b""

        self.client_private_key = None
        self.client_public_key = None
        self.client_session_id = None

        self.server_private_key = None
        self.server_public_key = None

        self.server_send_seq = 0
        self.client_recv_seq = 0
        self.client_send_seq = 0
        self.server_recv_seq = 0

        self.client_write_key = None
        self.client_write_iv = None
        self.server_write_key = None
        self.server_write_iv = None

        self.application_data_step = 0
        self.step = 0
