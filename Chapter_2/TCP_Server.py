import socket
import threading

IP = '0.0.0.0'
PORT = 9998

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT)) #1
    server.listen(5) #2
    print(f'[*] Listening on {IP}:{PORT}')

    while True:
        client, addr = server.accept() #3
        print(f'[*] Accepted connection from {addr[0]}:{addr[1]}')
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start() #4

def handle_client(client_socket): #5
    with client_socket as sock:
        request = sock.recv(1024)
        print(f'[*] Received: {request.decode("utf-8")}')
        sock.send(b'ACK')

if __name__ == '__main__':
    main()
