import sys
import subprocess
import socket
import threading
import rsa

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

def generate_key_pair():
    return rsa.newkeys(1024)

def get_ip_address():
    return input("Enter the IP address: ")

def get_choice():
    return input("Do you want to host (1) or connect (2): ")

def setup_server(ip_address):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip_address, 9999))
    server.listen()
    print(f"Server listening on {ip_address}:9999")
    client, _ = server.accept()
    client.send(public_key.save_pkcs1("PEM"))
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
    return client, public_partner

def setup_client(ip_address):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip_address, 9999))
    print(f"Connected to {ip_address}:9999")
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(public_key.save_pkcs1("PEM"))
    return client, public_partner

def send_message(c, public_partner):
    while True:
        try:
            message = input("You: ")
            if message.lower() == 'exit':
                break
            c.send(rsa.encrypt(message.encode(), public_partner))
        except Exception as e:
            print(f"Error sending message: {e}")
            break

def receive_message(c, private_key):
    while True:
        try:
            decrypted_message = rsa.decrypt(c.recv(1024), private_key).decode()
            print("Partner:", decrypted_message)
            if decrypted_message.lower() == 'exit':
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def close_connection(c):
    try:
        c.shutdown(socket.SHUT_RDWR)
        c.close()
    except Exception as e:
        print(f"Error closing connection: {e}")

if __name__ == "__main__":
    public_key, private_key = generate_key_pair()
    public_partner = None

    ip_address = get_ip_address()
    choice = get_choice()

    if choice == "1":
        client, public_partner = setup_server(ip_address)
    elif choice == "2":
        client, public_partner = setup_client(ip_address)
    else:
        sys.exit()

    threading.Thread(target=send_message, args=(client, public_partner)).start()
    threading.Thread(target=receive_message, args=(client, private_key)).start()

    # Wait for the threads to finish
    for thread in threading.enumerate():
        if thread != threading.current_thread():
            thread.join()

    # Close the connection when the threads finish
    close_connection(client)
