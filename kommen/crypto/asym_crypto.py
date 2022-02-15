#! /usr/bin/env python

"""asym-crypto.py: Asymmetric cryptographic methods to support confidentiality and integrity"""

# imports
import pathlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512
from base64 import b64encode, b64decode

from kommen_shared.hash_crypto import HashCryptographyHandler

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class AsymmetricCryptographyHandler:
    """

    Asymmetric Cryptographic methods to handle keys and cryptograhic operations
    
    Attributes:

    Functions:
        do_keys_exist() -- check if a key pair exists 
        create_keys() -- create a new RSA key pair in local keystore
        remove_keys() -- remove keys from local keystore
        sign() -- use private key to sign an object (generate checksum)
        is_sign_valid() -- check if provided signature is cryprographically valid
        encrypt() -- encrypt object using a public key
        decrypt() -- decrypto object using a private key

    """

    def do_keys_exist(self, keypair=None): # Finished and tested 8/25
        """Checks for existence of key pair 
        
        Args:
            keypair (None): default value which causes a check for the server key pair
            keypair (tuple): passed value which causes a check for the indicated client key pair 

        Returns:
            exists (bool): True if exists, False otherwise
        
        """

        exists = False
        
        if keypair is not None: 
            private_key = pathlib.Path(r'../keys/' + keypair[0])
            public_key = pathlib.Path(r'../keys/' + keypair[1])
        else:
            private_key = pathlib.Path(r'../keys/private.pem')
            public_key = pathlib.Path(r'../keys/public.pem')

        if private_key.exists() and public_key.exists():
            exists = True

        return exists

    def create_keys(self, client=None): # Finished and tested 8/25
        """Creates a 2048 bit RSA key pair and outputs as private.pem and public.pem files
        
        Args:
            client (None): default value which is handled as the server key pair
            client (str): passed value which is used as unique client identifier (maybe later we use index from keys.db)

        Returns:
            is_created (bool): True for success, False otherwise.
            name ( ): 
        
        """ 
        is_created = False
        key = RSA.generate(2048) #should this be a config setting?
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        hasher = HashCryptographyHandler()
        name = hasher.create_hash(str(public_key))

        try:
            if client is not None:
                with open(pathlib.Path(r'keys/' + client + '_private.pem'), 'wb') as private_file:
                    private_file.write(private_key)
            
                with open(pathlib.Path(r'keys/' + client +  '_public.pem'), 'wb') as public_file:
                    public_file.write(public_key)
            else:
                with open(pathlib.Path(r'keys/' + name.hexdigest() + '_private.pem'), 'wb') as private_file:
                    private_file.write(private_key)
            
                with open(pathlib.Path(r'keys/' + name.hexdigest() + '_public.pem'), 'wb') as public_file:
                    public_file.write(public_key)
        except Exception as e:
            print('Error writing key to file: ' + str(e)) #add logging
        else:
            is_created = True

        return is_created, name.hexdigest()

    def remove_keys(self, privkey, pubkey): # Finished and tested 8/26
        """Deletes indicated key pair
        
        Args:
            privkey (str): hexadecimal digest of client's private key
            pubkey (str): hexadecimal digest of client's public key

        Returns:
            is_removed (bool): The return value. True for success, False otherwise.
        
        """ 
        is_removed = False

        private_key = pathlib.Path(r'keys/' + privkey.lower() + '_private.pem')
        public_key = pathlib.Path(r'keys/' + pubkey.lower() +  '_public.pem')

        try:
            pathlib.Path.unlink(private_key)
            pathlib.Path.unlink(public_key)
            is_removed = True
        except Exception as e:
            print('Error deleting key file: ' + str(e)) #add logging

        
        return is_removed

    def sign(self, obj, privkey=None): # Finished and tested 8/26
        """Creates cryptographic signature (checksum) of indicated object.
        
        Args:
            obj (str): object to be signed as bytearray
            privkey (none): default value which is handled as the server private key to be used in generating the signature.
            private (str): passed value indicating a client private key .pem file
 
        Returns:
            signature (str): The return value is a cryptographic signature 
        
        """
        if privkey is not None:
            private_key = pathlib.Path(r'../keys/' + privkey)
        else:
            private_key = pathlib.Path(r'../keys/private.pem')
        
        try:
            with open(private_key, 'r') as k:
                key = RSA.importKey(k.read())
            
            hash = SHA512.new(obj)

            signer = PKCS1_v1_5.new(key)
            signature = signer.sign(hash)

            return signature
        except IOError as e:
            print('Error loading private key: ' + str(e)) #add logging

    def is_sign_valid(self, obj, signature, pubkey=None): # Finished and tested 8/26
        """Checks if provided signature is cryptographically valid and returns Boolean
        
        Args:
            obj: any object previously signed and to be validated
            signature (str): the signature string to be validated
            pubkey (None): default value which is handled as the server public key to be used in validating the signature
            pubkey (str): passed value indicated the client public key .pem to be used in validating a signature

        Returns:
            is_valid (bool): True for valid, False otherwise.
        
        """
        is_valid = False

        if pubkey is not None:
            public_key = pathlib.Path(r'../keys/' + pubkey)
        else:
            public_key = pathlib.Path(r'../keys/public.pem')

        try:
            with open(public_key, 'rb') as f:
                key = RSA.importKey(f.read())
        
            hasher = SHA512.new(obj)
            verifier = PKCS1_v1_5.new(key)
        
            if verifier.verify(hasher, signature):
                is_valid = True
        except Exception as e:
            print('Error loading private key: ' + str(e)) #add logging
        else:
            return is_valid

    def encrypt(self, plaintext, pubkey=None): # Finished and tested 8/26
        """Encrypts provided plaintext and returns ciphertext
        
        Args:
            plaintext (str): the plaintext to be encrypted
            pubkey (None): default value which indicates server public key
            pubkey (str): passed value indicating a client public key .pem file
            
        Returns:
            cipher.encrypt(): encrypted plaintext
        
        """
        if pubkey is not None:
            public_key = pathlib.Path(r'../keys/' + pubkey)
        else:
            public_key = pathlib.Path(r'../keys/public.pem')

        try:
            with open(public_key, "rb") as k:
                key = RSA.importKey(k.read())

            cipher = Cipher_PKCS1_v1_5.new(key)
            return cipher.encrypt(plaintext.encode()) # I don't think I should do this here...
        except Exception as e:
            print('Error writing key to file: ' + str(e)) #add logging
    
    def decrypt(self, ciphertext, privkey=None): # Finished and tested 8/26
        """Decrypts provided ciphertext and returns plaintext
        
        Args:
            ciphertext (str): the ciphertext to be decrypted
            privkey (None): default value which indicates server private key
            privkey (str): a filepath to a private key .pem file

        Returns:
            decipher.decrypt(): decrypted ciphertext
        
        """
        if privkey is not None:
            private_key = pathlib.Path(r'../keys/' + privkey)
        else:
            private_key = pathlib.Path(r'../keys/private.pem')

        try:
            with open(private_key, "rb") as k: #privkey is a filepath to private key .pem file
                key = RSA.importKey(k.read())

            decipher = Cipher_PKCS1_v1_5.new(key)
            return decipher.decrypt(ciphertext, None).decode()
        except Exception as e:
            print('Error writing key to file: ' + str(e)) #add logging