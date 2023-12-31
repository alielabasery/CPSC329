import sys
import subprocess
import socket
import threading
import rsa
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QRadioButton, QPushButton, QTextEdit, QHBoxLayout, QSizePolicy

def install_rsa_package():
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rsa"])
        import rsa
        return rsa
    except subprocess.CalledProcessError as e:
        print(f"Error installing 'rsa': {e}")
        sys.exit(1)
    except ImportError:
        print("Error importing 'rsa'")
        sys.exit(1)

try:
    rsa = __import__('rsa')
except ImportError:
    print("Installing the 'rsa' package...")

    rsa = install_rsa_package()

class ChatApp(QWidget):
    def __init__(self):
        super().__init__()

        self.public_key, self.private_key = self.generate_key_pair()
        self.public_partner = None
        self.client = None

        self.init_ui()

    def init_ui(self):
        self.ip_label = QLabel('Enter IP address:')
        self.ip_entry = QLineEdit()

        self.radio_host = QRadioButton('Host')
        self.radio_connect = QRadioButton('Connect')

        self.start_button = QPushButton('Start Chat')
        self.stop_button = QPushButton('Stop Chat')
        self.stop_button.setEnabled(False)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)

        self.input_text = QTextEdit()

        layout = QVBoxLayout()
        layout.addWidget(self.ip_label)
        layout.addWidget(self.ip_entry)
        layout.addWidget(self.radio_host)
        layout.addWidget(self.radio_connect)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.output_text)
        layout.addWidget(self.input_text)

        self.setLayout(layout)

        self.start_button.clicked.connect(self.start_chat)
        self.stop_button.clicked.connect(self.stop_chat)

    def generate_key_pair(self):
        return rsa.newkeys(1024)

    def setup_server(self, ip_address):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((ip_address, 9999))
        server.listen()
        print(f"Server listening on {ip_address}:9999")
        client, _ = server.accept()
        client.send(self.public_key.save_pkcs1("PEM"))
        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
        return client, public_partner

    def setup_client(self, ip_address):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip_address, 9999))
        print(f"Connected to {ip_address}:9999")
        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
        client.send(self.public_key.save_pkcs1("PEM"))
        return client, public_partner

    def send_message(self):
        message = self.input_text.toPlainText().strip()
        if message.lower() == 'exit':
            self.stop_chat()
            return
        try:
            self.client.send(rsa.encrypt(message.encode(), self.public_partner))
            self.input_text.clear()
        except Exception as e:
            print(f"Error sending message: {e}")
            self.stop_chat()

    def receive_message(self):
        while True:
            try:
                decrypted_message = rsa.decrypt(self.client.recv(1024), self.private_key).decode()
                self.output_text.append(f"Partner: {decrypted_message}")
                if decrypted_message.lower() == 'exit':
                    self.stop_chat()
                    break
            except Exception as e:
                print(f"Error receiving message: {e}")
                self.stop_chat()
                break

    def start_chat(self):
        ip_address = self.ip_entry.text()
        if self.radio_host.isChecked():
            self.client, self.public_partner = self.setup_server(ip_address)
        elif self.radio_connect.isChecked():
            self.client, self.public_partner = self.setup_client(ip_address)
        else:
            return

        threading.Thread(target=self.send_message).start()
        threading.Thread(target=self.receive_message).start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_chat(self):
        self.close_connection()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def close_connection(self):
        try:
            self.client.shutdown(socket.SHUT_RDWR)
            self.client.close()
        except Exception as e:
            print(f"Error closing connection: {e}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    chat_app = ChatApp()
    chat_app.show()
    sys.exit(app.exec_())
