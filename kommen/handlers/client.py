#! /usr/bin/env python

"""client.py: """

# imports


__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class ClientHandler:
    """

    Client class to expose specific attributes
    
    Attributes:

    Functions:

    """

    def __init__(self):
        self.__name = None
        self.__id = None
        self.__status = 0
        self.__pubkey = " "
        self.__privkey = " "
        self.__symkey = " "
        self.__count = 1

    @property
    def client_name(self):
        return self.__name

    @client_name.setter
    def client_name(self, name):
        self.__name = name

    @property
    def client_id(self):
        return self.__id

    @client_id.setter
    def client_id(self, client_id):
        self.__id = client_id

    @property
    def client_status(self):
        return self.__status

    @client_status.setter
    def client_status(self, status):
        self.__status = status
    
    @property
    def client_pubkey(self):
        return self.__pubkey

    @client_pubkey.setter
    def client_pubkey(self, pubkey):
        self.__pubkey = pubkey

    @property
    def client_privkey(self):
        return self.__privkey

    @client_privkey.setter
    def client_privkey(self, privkey):
        self.__privkey = privkey

    @property
    def client_symkey(self):
        return self.__symkey
    
    @client_symkey.setter
    def client_symkey(self, symkey):
        self.__symkey = symkey

    @property
    def client_count(self):
        return self.__count
    
    @client_count.setter
    def client_count(self, count):
        self.__count = count