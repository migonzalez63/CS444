# Written by Meisam Navaki, rewritten by Nick Aase maintained by crandall@cs.unm.edu
# All phrases should be more than 256 bits
import socket
from aes import AESCipher
from rsa import RSACipher


class Server451:
    def __init__(self, ipaddress, port):
        # Create TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind socket to port
        server_address = (ipaddress, port)
        try:
            self.sock.bind(server_address)
        except OSError:
            print('Address {} already in use'.format(server_address))
        # Listen for incoming connections
        self.sock.listen(10)

        self.rsa = RSACipher()

    def _getSessionKey(self):
        """
        Get the AES session key be decrypting the RSA ciphertext
        """
        try:
            AESEncrypted = self.cipher[:256]
            AESKey = self.rsa.decrypt(AESEncrypted)
            return AESKey[(len(AESKey)-32):]
        except ValueError:
            return False

    def _myDecrypt(self):
        """
        Decrypt the client message:
        AES key encrypted by the
        public RSA key of the server + message encrypted by the AES key
        """
        messageEncrypted = self.cipher[256:]
        AESKey = self._getSessionKey()
        aes = AESCipher(AESKey)
        return aes.decrypt(messageEncrypted)

    def stand_up(self):
        print('Waiting for a connection...')  # Wait for a conneciton
        connection, client_address = self.sock.accept()

        try:
            # Receive the data
            self.cipher = connection.recv(2048)
            print("Message Received...")

            message = self._myDecrypt()
            if message:
                print("Decrypted successfully!")
                aes = AESCipher(self._getSessionKey())
                msg = aes.encrypt(message.upper())
                connection.sendall(msg)
            else:
                connection.sendall("Couldn't decrypt!")
        finally:
            # Clean up the connection
            connection.close()
        return True
