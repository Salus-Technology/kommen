#! /usr/bin/env python

"""sym-crypto.py: Symmetric cryptographic methods to support confidentiality and integrity"""

# imports
import pathlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class SymmetricCryptographyHandler:

    __key = ' '

    def __init__(self, keyfile=None):
        if keyfile is None:
            self.__key = ' '
        else:
            self.__key = keyfile

    def does_key_exist(self, client_key):
        """
            Args:

            Returns:
        """
        exists = False

        if client_key.exists():
            return True
        else:
            try:
                self.create_key()
            except Error as e:
                return e

        return exists

    def create_key(self, client):
        """
            Args:

            Returns:
        """
        key = get_random_bytes(32)

        with open(pathlib.Path(r'keys/' + client + '.bin'), 'wb') as private_file:
                    private_file.write(key)
        
    def create_pad(plaintext):
        """
            Args:

            Returns:
        """
        padding = b'\0' * (AES.block_size - len(plaintext) % AES.block_size)
        return plaintext + padding

    def encrypt(self, key, plaintext):
        """
            Args:

            Returns:
        """
        
        message = self.pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        return iv + cipher.encrypt(message)
        
    
    def decrypt(self, key, ciphertext):
        """
            Args:

            Returns:
        """
        
        plaintext = ' '
        return plaintext