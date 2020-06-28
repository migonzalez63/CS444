import argparse
import os
from time import sleep
from Crypto import Random
from server451 import Server451

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port",
                    help='starting port where the server is listening on',
                    required=True)
parser.add_argument("-n", "--number",
                    help='the number of ports above -p to listen',
                    required=True)
args = parser.parse_args()

for i in range(int(args.number)):
    pid = os.fork()
    Random.atfork()
    if pid == 0:
        port = int(args.port) + i
        server = Server451('0.0.0.0', port)
        while True:
            finished = server.stand_up()
            if finished is True:
                print("Processed client message on port {}".format(port))
                sleep(1)
        exit()
