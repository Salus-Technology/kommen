#! /usr/bin/env python

"""server.py: """

# import handlers
#import database
import os

# import shared modules
#from crypto import asym_crypto 
#from crypto import sym_crypto 

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2022, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class ServerHandler():
    """

    Methods to handle the Kommen server
    
    Attributes:

    Functions:
        initialize_server() --
        get_status() --

    """ 

    def __init__(self):
        pass

    def initialize_server(self):
        does_datadir_exist = False
        does_keysdir_exist = False
        do_keys_exist = False
        data_path = '../../data'
        keys_path = '../../data/keys/'

        try:
            does_datadir_exist = os.path.isdir(data_path) #if false, create the dir
            print(does_datadir_exist)

            does_keysdir_exist = os.path.isdir(keys_path) #if false, create the dir
            print(does_keysdir_exist)
        except os.error as e:
            print(str(e))

    def get_status(self):
        pass


    def create_dir(self, dir):
        pass

    def create_keys(self):
        pass

if __name__ == "__main__":
    server = ServerHandler()

    server.initialize_server()


