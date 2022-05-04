

"""The TCP/IP Server component for Kommen"""

# standard library imports
import sys
import json
import socket
import multiprocessing

# third party imports

# local packages
from handlers import preamble
from handlers import firewall

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
        fw = firewall.FirewallHandler()

        try:
            print("Connected %r at %r", connection, address)

            while True:
                data = connection.recv(1024)
                
                #need to differentiate between a rac data payload, a preamble versus other
                if len(data) in range(131, 151):

                    #check if the client id is valid and the preamble is sanitized
                    is_preamble = pre.handle_premable(data)
                    
                    # if the preamble is good, we ack we process the racs into the firewall
                    if is_preamble:
                        connection.sendall("Preamble Acknowledged".encode())
                    else:
                        connection.sendall("There was an error with in the preamble")
                elif len(data) == 6:
                    # we need access to the client dictionary here i think...
                    fw.remove_knock_chains() # we need to remove any existing knock chains for the client
                    fw.add_knock_chains() # we need to store incoming rac for each client until we get all three and then add the chains
                else:
                    print('Invalid preamble received') #placeholder...this applies to anything not a preamble or rac

                #this stops infinite looping
                if data.decode("utf-8").strip() == "":
                    print("Socket closed remotely")
                    break
                
                print("Received data %r", data)

                #if all of the above is good, we send ack for racs being ready || if not good, we send resend
                #connection.sendall(data)
                #print("Sent data")

        except Exception as e:
            print("An exception has occured: " + str(e))
        finally:
            connection.close()
 

if __name__ == "__main__":
    server = KommenServer("0.0.0.0", 5002)

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