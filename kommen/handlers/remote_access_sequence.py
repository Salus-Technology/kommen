#! /usr/bin/env python

"""remote-access-request.py: """

# imports


__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class RemoteAccessCodeSequenceHandler:
    """
    Methods to generate and verify remote access code sequences
    
    Attributes:

    Functions:
        get_racs() -- returns the value of a private field racs
        generate_racs() -- returns 0 when successfully generated racs
        verify_racs() -- checks individual rac and modifies if invalid
        
    """
    def __init__(self):
        self.__blacklist = [0, 80, 5002]
        self.__rar_length = 5
        self.__racs = []

    def get_racs(self):
        """ """
        return self.__racs[0]

    def generate_racs(self, rac):
        """ """
        try:
            self.__racs.append([int((rac[i:i + self.__rar_length])) for i in range(0, len(rac), self.__rar_length)])
            return 0
        except:
            return 1

    def verify_racs(self):
        """ """
        is_verified = False
        
        while is_verified is False:
            for index, rac in enumerate(self.__racs[0]):              
                blacklist_flag = self.__check_blacklist(rac)
                if blacklist_flag is False:
                    self.__racs[0][index] = int(rac) + int(rac) + 1
                    
                
                rac_value_flag = self.__check_rac_value(rac)
                if rac_value_flag is False:
                    self.__racs[0][index] = int(rac) - 65535

            if blacklist_flag is True and rac_value_flag is True:
                is_verified = True

        return is_verified
    
    def __check_rac_value(self, rac):
        if int(rac) > 65535:
            rac_value_flag = False
        else:
            rac_value_flag = True
        
        return rac_value_flag

    def __check_blacklist(self, rac):
        
        if rac in self.__blacklist:
            blacklist_flag = False
        else:
            blacklist_flag = True

        return blacklist_flag