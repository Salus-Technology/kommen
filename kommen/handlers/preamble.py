#! /usr/bin/env python

"""preamble.py: """

import sys
import json
import socket
import multiprocessing

#sys.path.insert(0, '../kommen_server')
#from handlers import firewall
#from handlers import clients
#from handlers import database
from crypto.asym_crypto import AsymmetricCryptographyHandler

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

def handle(connection, address):
    try:
        print("Connected %r at %r", connection, address)

        while True:
            data = connection.recv(1024)
            #we process the preamble here
            payload = handle_premable(data, client_id)

            #this is a simple test of plaintext payload
            #client_id, count, pubkey = data.decode("utf-8").strip().split(',') # decode and split on comma to get client_id, counter
            #print(client_id + 'is at ' + count + ' with key' + pubkey)
            
            
            # check client_id and count against database


            #if data.decode("utf-8").strip() == "":
            #    print("Socket closed remotely")
            #    break
            #print("Received data %r", data)

            #connection.sendall(data)
            #print("Sent data")           
    except Exception as e:
        print("An exception has occured: " + str(e))
    finally:
        connection.close()

def handle_premable(data, client_id):
    #decrypt payload
    try:
        decryptor = AsymmetricCryptographyHandler()
        plaintext = decryptor.decrypt(data, client_id)
    except Exception as e:
        print("An exception has occured: " + str(e))

    #Server checks clients object for client_id:
    #if the client_id is in clients, server replies with a received_valid message
    #if the client_id is not in clients, server replies with a received_invalid message
    
    return plaintext

def handle_exchange():
    pass

def handle_synchronize():
    pass

def handle_racs():
    pass

def is_valid_preamble(client_id, count):
    db = database.DatabaseHandler()
    clients = json.dumps(db.read())
    
    if client_id in clients:
        print("found client_id")
    else:
        print("didn't find client_id")
    

class PreambleHandler: 
    """
    
    """

    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(1)

        while True:
            conn, address = self.server_socket.accept()
            
            process = multiprocessing.Process(target=handle, args=(conn, address))
            process.daemon = True
            process.start()
    


if __name__ == "__main__":
    server = PreambleHandler("0.0.0.0", 5002)

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