import socket

# function to start the server
def start_server(host='0.0.0.0', port=8080):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(100)
    print(f"Server listening on {host}:{port}")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection received from {addr}")
        client_socket.send(b"Hello from server!")
        client_socket.close()

if __name__ == "__main__":
    start_server()
