#! /usr/bin/env python

"""server.py: """

import os
import sys

#sys.path.append('..')

from crypto import asym_crypto 
from crypto import sym_crypto 


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
        is_datadir = False
        is_keydir = False
        is_privkey = False
        is_pubkey = False
        
        data_path = '../../data'
        keys_path = '../../data/keys/'
        server_privkey = keys_path + 'server_private.pem' 
        server_pubkey = keys_path + 'server_public.pem'

        crypto = asym_crypto.AsymmetricCryptographyHandler()

        try:
            is_datadir = os.path.isdir(data_path) #if false, create the dir
            print(is_datadir)

            is_keydir = os.path.isdir(keys_path) #if false, create the dir
            print(is_keydir)

            # there is a do_keys_exist method in the crypto handlers!
            is_privkey = os.path.isfile(server_privkey)
            print(is_privkey)

            is_pubkey = os.path.isfile(server_pubkey)
            print(is_pubkey)

            if is_privkey is False or is_pubkey is False:
                crypto.create_keys('server')

            return is_datadir,is_keydir

        except os.error as e:
            print(str(e))

    def get_status(self):
        pass

    def create_dir(self, dir):
        pass

    def create_keys(self):
        crypto = asym_crypto.AsymmetricCryptographyHandler()

if __name__ == "__main__":
    server = ServerHandler()

    server.initialize_server()


