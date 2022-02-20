#! /usr/bin/env python

"""registration.py: """

# import handlers
from handlers import database
from handlers import client

# import shared modules
from crypto import asym_crypto 
from crypto import sym_crypto 

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class RegistrationHandler:
    """

    Methods to handle client registration
    
    Attributes:

    Functions:
        register_client(str) --
        delete_client(str) --

    """ 
    def __init__(self):
        self.db = database.DatabaseHandler()

    def register_client(self, client_id=None):
        
        # outer conditional to handle if client_id is none or 
        
        # generate keypair and get ids
        asym = asym_crypto.AsymmetricCryptographyHandler()
        sym = sym_crypto.SymmetricCryptographyHandler()

        created = asym.create_keys()

        if created[0] is True:
            # build a new client object ; need to get the pubkey hash back somehow to set some of these attributes
            new_client = client.ClientHandler()
            new_client.client_name = created[1]
            new_client.client_id = created[1]
            new_client.client_status = 1
            new_client.client_pubkey = created[1]
            new_client.client_privkey = created[1]
            new_client.client_symkey = created[1]
            new_client.client_count = 1

        # write the new client to the database
        self.db.write(new_client)

        #return the new_client so that the service can add it to the running collection
        return new_client

    def rekey_client(self, client):
        asym = asym_crypto.AsymmetricCryptographyHandler()
        
        keypair = (client.client_privkey, client.client_pubkey) #this doesn't appear to be working correctly

        #revoke old keypair
        result = asym.remove_keys(keypair) #this doesn't appear to be working correctly

        #create new keypair
        new_keys = asym.create_keys()

        #update the client with the new key information if new_keys[0] is True
        client.client_privkey = new_keys[1]
        client.client_pubkey = new_keys[1]

        #update database
        self.db.update(client, 'rekey') # we need to capture the new identity 

    def delete_client(self, client_id): #this needs converted over to objects?
        is_success = self.db.remove(client_id)

        return is_success

    def disable_client(self, client):
        is_success = self.db.update(client, 'disable')

        return is_success

    def enable_client(self, client):
        is_success = self.db.update(client, 'enable')

        return is_success

    def revoke_client(self, client):
        is_revoked = False
        asym = asym_crypto.AsymmetricCryptographyHandler()

        is_revoked = asym.remove_keys(client.client_privkey, client.client_pubkey)

        return is_revoked

    def get_clients(self):
        pass