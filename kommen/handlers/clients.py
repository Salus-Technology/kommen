#! /usr/bin/env python

"""clients.py: """

# imports
from handlers.client import ClientHandler as client

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class ClientsHandler:
    """

    Clients class to expose iterable collection of client objects
    
    Attributes:

    Functions:

    """

    def __init__(self):
        self._clients = list()
        self._index = 0
    
    def __iter__(self):
        return self
    
    def __next__(self):
        if self._index < len(self._clients):
            result = self._clients[self._index]
            self._index += 1

            return result
        
        raise StopIteration
        
    def add_client(self, c: client):
        self._clients.append(c)

    def remove_client(self, c: client):
        self._clients.remove(c) #this is sketch

    def get_client(self):
        return self._clients[-1].client_name



