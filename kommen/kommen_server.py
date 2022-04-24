

"""The TCP/IP Server component for Kommen"""

# standard library imports
import sys
import json
import socket
import multiprocessing

# third party imports

# local packages
from handlers import preamble

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2022, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"


class KommenServer:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(1)

        while True:
            conn, address = self.server_socket.accept()
            
            process = multiprocessing.Process(target=self.handle, args=(conn, address))
            process.daemon = True
            process.start()


    def handle(self, connection, address):

        pre = preamble.PreambleHandler()

        try:
            print("Connected %r at %r", connection, address)

            while True:
                data = connection.recv(1024)
                #we process the preamble here

                plaintext = pre.handle_premable(data)
                print(plaintext)
                
                # if the preamble is good, we ack we process the racs into the firewall


                #this stops infinite looping
                if data.decode("utf-8").strip() == "":
                    print("Socket closed remotely")
                    break
                print("Received data %r", plaintext)

                #if all of the above is good, we send ack for racs being ready || if not good, we send resend
                connection.sendall(data)
                print("Sent data")

        except Exception as e:
            print("An exception has occured: " + str(e))
        finally:
            connection.close()


if __name__ == "__main__":
    server = KommenServer("0.0.0.0", 5003)

    try:
        print("Listening")
        server.start()
    except Exception as e:
        print("Unexpected exception: " + str(e))
    finally:
        print("Shutting down")
        for process in multiprocessing.active_children():
            print("Shutting down process %r", process)
            process.terminate()
            process.join()
    
    print("All done")