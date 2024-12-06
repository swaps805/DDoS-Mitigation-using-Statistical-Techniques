import socket

SERVER_IP = "192.168.1.116"
PORT = 8080

message = " !"
while(1):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client_socket.connect((SERVER_IP, PORT))
        print(f"Connected to server at {SERVER_IP}:{PORT}")

        client_socket.sendall(message.encode('utf-8'))
        print(f"Message sent: {message}")

        client_socket.close()
        print("Connection closed.")
    except Exception as e:
        print(f"An error occurred: {e}")


