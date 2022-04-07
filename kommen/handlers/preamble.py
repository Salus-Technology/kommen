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


__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

 
class PreambleHandler: 
    """
    
    """

    def handle_premable(self, data):
        plaintext = tuple(x for x in data.decode("utf-8").strip().split(','))
        #client_id, count, pubkey = data.decode("utf-8").strip().split(',') # decode and split on comma to get client_id, counter
        #decrypt payload
        #try:
            #decryptor = AsymmetricCryptographyHandler()
            #plaintext = decryptor.decrypt(data, client_id)
        #except Exception as e:
        #    print("An exception has occured: " + str(e))

        #Server checks clients object for client_id:
        #if the client_id is in clients, server replies with a received_valid message
        #if the client_id is not in clients, server replies with a received_invalid message
        
        #return plaintext as tuple(client_id, count, key)
        return plaintext

    def handle_exchange(self):
        pass

    def handle_synchronize(self):
        pass

    def handle_racs(self):
        pass

    def is_valid_preamble(self, client_id, count):
        db = database.DatabaseHandler()
        clients = json.dumps(db.read())
        
        if client_id in clients:
            print("found client_id")
        else:
            print("didn't find client_id")