#! /usr/bin/env python

"""hash-crypto.py: Hashing methods to support integrity"""

# imports
from Crypto.Hash import SHA256

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class HashCryptographyHandler:
    """

    Hashing methods to support integrity
    
    Attributes:

    Functions:
        create_hash(str) -- create a new SHA 256 checksum of the provided object
        verify_hash(str, str) -- compare the provided SHA 256 checksum to the generated checksum of the provided object

    """

    def create_hash(self, object):
        encoded_object = object.encode()
        bytes_object = bytearray(encoded_object)
        hash = SHA256.new(data=bytes_object) #should the algorithm and bits be config options?

        return hash

    def verify_hash(self, provided_hash, object):
        is_hash_valid = False

        current_hash = self.create_hash(object)
        
        if provided_hash == current_hash.hexdigest():
            is_hash_valid = True

        return is_hash_valid