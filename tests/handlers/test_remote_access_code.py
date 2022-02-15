#!/usr/bin/env python

from remote_access_code import RemoteAccessCodeHandler
from unittest import TestCase

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"



class TestRemoteAccessCodeHandler(TestCase):
    
    test_rac = RemoteAccessCodeHandler(None, None)
    rac = ' '

    def test_generate_rac(self):
        self.rac = self.test_rac.generate_rac(1)
        print(self.rac)
        self.assertEqual(self.rac, '000001592370379', "Generated RAC does not match")

    def test_verify_rac(self):
        self.rac = self.test_rac.generate_rac(1)
        
        is_valid = self.test_rac.verify_rac(self.rac, 1)
        self.assertTrue(is_valid)
