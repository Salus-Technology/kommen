#!/usr/bin/env python

from remote_access_sequence import RemoteAccessCodeSequenceHandler
from unittest import TestCase

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"


class TestRemoteAccessSequenceHandler(TestCase):
    

    def test_generate_racs(self):
        test_racs = RemoteAccessCodeSequenceHandler()
        rac = '000001592370379'
        result = test_racs.generate_racs(rac)
        print(result)
        self.assertEqual(result, 0, "Generating RACS failed")

    def test_verify_racs(self):
        test_racs = RemoteAccessCodeSequenceHandler()
        rac = '000001592370379'

        test_racs.generate_racs(rac)
        
        result = test_racs.verify_racs()

        self.assertTrue(result, "The RACS is not valid")
    
    def test_get_racs(self):
        test_racs = RemoteAccessCodeSequenceHandler()
        rac = '000001592370379'
        racs = []

        test_racs.generate_racs(rac)
        test_racs.verify_racs()
        racs.append(test_racs.get_racs())
        
        self.assertEqual(racs[0], [1, 15923, 4844], "The RACS don't match based on the RAC seed")