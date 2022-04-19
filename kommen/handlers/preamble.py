#! /usr/bin/env python

"""preamble.py: """

import re
import sys
import json
import socket
import multiprocessing

#sys.path.insert(0, '../kommen_server')
#from handlers import firewall
#from handlers import clients
#from handlers import database
from database import DatabaseHandler


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
        payload = tuple(x for x in data.decode("utf-8").strip().split(',')) # this throws an error when the client ctrl-c disconnects...need to wrap for robustness
        #client_id, count, pubkey = data.decode("utf-8").strip().split(',') # decode and split on comma to get client_id, counter


        #Server checks clients object for client_id:
        #if the client_id is in clients, server replies with a received_valid message
        is_valid = self.is_valid_preamble(payload[0], payload[1])
        
        #if the client_id is not in clients, server replies with a received_invalid message
        
        #if the payload is sanitized, we return true else false
        is_sanitized = self.sanitize_premable(payload)

        if is_sanitized:
            print('True')
        else:
            print('False')

        #return plaintext as tuple(client_id, count, key)
        return payload

    def handle_exchange(self):
        pass

    def handle_synchronize(self):
        pass

    def handle_racs(self):
        pass

    def sanitize_premable(self, payload):
        is_sanitized = False
        try:
            client = re.match('[a-f0-9]{64}$', payload[0])
            #counter = re.match(r'^[0-9]+$', int(payload[1]))
            #key = re.match(r'/^[a-f0-9]{64}$/gi', str(payload[0]))
        except Exception as e:
            print(str(e))
        
        #validate client_id is size and char set expected
        if client:
            sanitized = True

        #validate counter is integer in expected range
        #if counter:
        #    sanitized = True

        #validate key is size and char set expected
        #if key:
        #    sanitized = True

        return is_sanitized

    def is_valid_preamble(self, client_id, count): # this works, need to change prints to Boolean returns
        db = DatabaseHandler()
        clients = json.dumps(db.read())
        
        if client_id in clients:
            print("found client_id")
        else:
            print("didn't find client_id")