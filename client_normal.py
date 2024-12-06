import socket
import random
from time import sleep

SERVER_IP = "172.18.0.30"
PORT = 8080

message = " !"
while(1):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client_socket.connect((SERVER_IP, PORT))
        print(f"Connected to server at {SERVER_IP}:{PORT}")
        
        # message = "hii"
        client_socket.sendall(message.encode('utf-8'))
        print(f"Message sent: {message}")

        response = client_socket.recv(1024)
        print(f"Response from server: {response.decode('utf-8', errors='replace')}")

        client_socket.close()
        print("Connection closed.")
        sleep(random.uniform(0.1,0.5))
    except Exception as e:
        print(f"An error occurred: {e}")


