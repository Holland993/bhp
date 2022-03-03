import socket

target_host = "127.0.0.1"
target_port = 9998

# create a socket object
try:
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mysocket.connect((target_host, target_port))
    print('Connected to host '+str(target_host)+' in port: '+str(target_port))
    message = mysocket.recv(1024)
    print("Message received from the server", message)

    while True:
        message = input("Enter your message > ")
        mysocket.send(bytes(message.encode('utf-8')))
        if message = 'quit':
            breake
except socket.errno as error:
    printpritn("Socket error ", error)
finally:
    mysocket.close()
