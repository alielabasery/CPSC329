import sys
import subprocess
import socket
import threading
import rsa
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QRadioButton, QPushButton, QTextEdit, QMessageBox
from PyQt5.QtCore import QObject, QThread, pyqtSignal, pyqtSlot

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

class WorkerSignals(QObject):
    receive_message_signal = pyqtSignal(str)
    close_connection_signal = pyqtSignal()

class Worker(QThread):
    def __init__(self, ip_address, is_host, public_key, private_key, parent=None):
        super(Worker, self).__init__(parent)
        self.client = None
        self.public_partner = None
        self.ip_address = ip_address
        self.is_host = is_host
        self.public_key = public_key
        self.private_key = private_key
        self.signals = WorkerSignals()

    def setup_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip_address, 9999))
        server.listen()
        print(f"Server listening on {self.ip_address}:9999")
        client, _ = server.accept()
        client.send(self.public_key.save_pkcs1("PEM"))
        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
        self.signals.receive_message_signal.emit(f"Connected to {self.ip_address}:9999")
        return client, public_partner

    def setup_client(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((self.ip_address, 9999))
            self.signals.receive_message_signal.emit(f"Connected to {self.ip_address}:9999")
        except ConnectionRefusedError as e:
            self.signals.receive_message_signal.emit(f"Connection refused. Is the server running on {self.ip_address}:9999?")
            self.signals.close_connection_signal.emit()  # Emit close connection signal
            return  # Stop the worker thread

        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
        client.send(self.public_key.save_pkcs1("PEM"))
        return client, public_partner

    def run(self):
        if self.is_host:
            self.client, self.public_partner = self.setup_server()
        else:
            self.client, self.public_partner = self.setup_client()

        threading.Thread(target=self.send_message).start()

        while True:
            try:
                if self.client is None or self.client.fileno() == -1:
                    break

                encrypted_message = self.client.recv(1024)
                if not encrypted_message:
                    break

                decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode()
                self.signals.receive_message_signal.emit(f"Partner: {decrypted_message}")

                if decrypted_message.lower() == 'exit':
                    break
            except Exception as e:
                self.signals.receive_message_signal.emit(f"Error receiving message: {e}")
                if "Decryption failed" in str(e):
                    self.signals.receive_message_signal.emit("Decryption failed. Ensure keys match.")
                break

        self.signals.close_connection_signal.emit()
    
    def send_message(self, message):
        try:
            if self.client is None or self.client.fileno() == -1:
                return

            if message.lower() == 'exit':
                self.signals.close_connection_signal.emit()
                return

            self.client.send(rsa.encrypt(message.encode(), self.public_partner))
        except Exception as e:
            self.signals.receive_message_signal.emit(f"Error sending message: {e}")
            self.signals.close_connection_signal.emit()
    
    def close_connection(self):
        try:
            if self.client:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except Exception as e:
            self.signals.receive_message_signal.emit(f"Error closing connection: {e}")

class ChatApp(QWidget):
    def __init__(self):
        super().__init__()

        self.public_key, self.private_key = self.generate_key_pair()
        self.worker = None

        self.init_ui()

    def init_ui(self):
        self.ip_label = QLabel('Enter IP address:')
        self.ip_entry = QLineEdit()

        self.fetch_ip_button = QPushButton('Fetch My IP')
        self.radio_host = QRadioButton('Host')
        self.radio_connect = QRadioButton('Connect')

        self.start_button = QPushButton('Start Chat')
        self.stop_button = QPushButton('Stop Chat')
        self.stop_button.setEnabled(False)
        self.send_button = QPushButton('Send')

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)

        self.input_text = QTextEdit()

        layout = QVBoxLayout()
        layout.addWidget(self.fetch_ip_button)
        layout.addWidget(self.ip_label)
        layout.addWidget(self.ip_entry)
        layout.addWidget(self.radio_host)
        layout.addWidget(self.radio_connect)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.output_text)
        layout.addWidget(self.input_text)
        layout.addWidget(self.send_button)

        self.setLayout(layout)

        self.fetch_ip_button.clicked.connect(self.fetch_ip_address)
        self.start_button.clicked.connect(self.start_chat)
        self.send_button.clicked.connect(self.send_message)
        self.stop_button.clicked.connect(self.stop_chat)

    def generate_key_pair(self):
        return rsa.newkeys(1024)

    def fetch_ip_address(self):
        try:
            # Try to fetch the local IP address using the socket library
            self.ip_entry.setText(socket.gethostbyname(socket.gethostname()))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error fetching IP address: {e}")

    def start_chat(self):
        ip_address = self.ip_entry.text()
        if self.radio_host.isChecked():
            self.worker = Worker(ip_address, True, self.public_key, self.private_key, self)
        elif self.radio_connect.isChecked():
            self.worker = Worker(ip_address, False, self.public_key, self.private_key, self)
        else:
            return

        self.worker.signals.receive_message_signal.connect(self.update_output_text)
        self.worker.signals.close_connection_signal.connect(self.stop_chat)
        self.worker.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_chat(self):
        if self.worker:
            self.worker.close_connection()
            self.worker.wait()  # Wait for the worker thread to finish
            self.worker = None

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    @pyqtSlot(str)
    def update_output_text(self, message):
        self.output_text.append(message)

    @pyqtSlot()
    def send_message(self):
        if self.worker:
            message = self.input_text.toPlainText()
            self.worker.send_message(message)
            self.input_text.clear()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    chat_app = ChatApp()
    chat_app.show()
    sys.exit(app.exec_())
