import argparse
import socket
import os
import time
from aes import AESCipher
from Crypto.PublicKey import RSA

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress",
                    help='ip address where the server is running',
                    required=True)
parser.add_argument("-p", "--port",
                    help='port where the server is listening on',
                    required=True)
parser.add_argument("-m", "--message",
                    help='message to send to the server',
                    required=True)
args = parser.parse_args()

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = (args.ipaddress, int(args.port))
sock.connect(server_address)
sock.settimeout(2)

AESKey = os.urandom(32)
while AESKey[0] == 0:  # Make sure there aren't leading 0s
    AESKey = os.urandom(32)

print("Using AES key : {}".format(AESKey.hex()))

# load server's public key
serverPublicKeyFileName = "serverPublicKey"
key = ""
with open(serverPublicKeyFileName, 'r') as f:
    key = RSA.importKey(f.read())

MESSAGE_LENGTH = 2048

encryptedKey = key.encrypt(AESKey, 32)[0]
aes = AESCipher(AESKey)
try:
    # Send data
    try:
        message = aes.encrypt(args.message)
    except ValueError:
        print("Client with port {} failed.".format(args.port))
        exit(1)
    msg = encryptedKey + message
    print('Sending: {}'.format(message.hex()))
    # msg: AES key encrypted by the public key of RSA
    #      + message encrypted by the AES key
    sock.sendall(msg)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)

    if amount_expected % 16 != 0:
        amount_expected += (16 - (len(message) % 16))

    answer = b''
    if amount_expected > amount_received:
        while amount_received < amount_expected:
            try:
                data = sock.recv(MESSAGE_LENGTH)
            except socket.timeout as e:
                err = e.args[0]

                if err == 'timed out':
                    print('Connection timed out, waiting for retry')
                    time.sleep(1)
                    continue
                else:
                    print('Another issue: {}'.format(e))
                    break
            except socket.error as e:
                print('Socket error: {}'.format(e))
                break
            amount_received += len(data)
            answer += data

    print('Received: {}'.format(aes.decrypt(answer)))

finally:
    sock.close()
