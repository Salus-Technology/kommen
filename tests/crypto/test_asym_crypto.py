#!/usr/bin/env python

from asym_crypto import AsymmetricCryptographyHandler
from unittest import TestCase

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class TestAsymCrypto(TestCase):
    crypto = AsymmetricCryptographyHandler()
    test_client = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
    test_keypair = ["9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08_private.pem", "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08_public.pem"]

    def test_do_keys_exist(self):
        result = self.crypto.do_keys_exist(keypair=self.test_keypair)
        self.assertTrue(result, "The keys do not exist")
        
    def test_create_keys(self):
        result = self.crypto.create_keys(client=self.test_client)
        self.assertTrue(result, "The keys could not be created")

    # remove_keys()
    def test_remove_keys(self):
        result = self.crypto.remove_keys(keypair=self.test_keypair)
        self.assertTrue(result, "The keys could not be removed")

    # sign()
    # is_sign_valid()
    # encrypt()
    # decrypt()

if __name__ == "__main__":
    test = TestAsymCrypto() 
    print("Testing if keys exist...should be False")
    test.test_do_keys_exist()
    
    print("Testing if we can create keys")
    test.test_create_keys()