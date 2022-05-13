#! /usr/bin/env python

"""remote-access-code.py: Methods to generate and verify a remote access code sequence"""

# imports
import array, time
import base64, hmac, hashlib
import pyotp as remote_access_code

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class RemoteAccessCodeHandler:

    __secret = 'DefaultSecretKey'
    __length = 15

    def __init__(self, secret=None, length=None):
        """
        Args:
            secret(str): the shared secret to seed remote access code
            length(int): length of the remote access code or number of integers

        Returns:

        """ 
        if secret != None:       
            self.__secret = base64.b32encode(secret.encode('ascii'))
            print(type(self.__secret))
        
        if length != None:
            self.__length = length

    def __convert_secret_base32(self):
        """Convert the secret to base32

        """
        return base64.b32decode(self.__secret)

    def generate_rac(self, counter):
        """Generate a remote access code 
            Args:
                counter(int):

            Returns:
                rac(int):
        """
        try:
            rac = remote_access_code.HOTP(self.__secret, self.__length, digest=hashlib.sha512)
        except Exception as e:
            print('Error in generate_rac at line 57 as ' + str(e))

        return rac.at(counter)

    def verify_rac(self, result, counter):
        """
            Args:
                result():
                counter():

            Returns:
                is_verified(bool): 
        """
        rac = remote_access_code.HOTP(self.__secret, self.__length, digest=hashlib.sha512)
        is_verified = rac.verify(result, counter)

        return is_verified