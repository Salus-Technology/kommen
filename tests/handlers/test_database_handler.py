#!/usr/bin/env python

#import sys
#sys.path.append('../handlers/')
#import database
import unittest
import sqlite3

from .context import *

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class TestDatabase(unittest.TestCase):
    """
    Test the database class for the ability to write and read to the kommen.db file
    """
    
    #def __init__(self):
    test_db = database.database()
    test_db_file = "kommen.db"
    test_client = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"

    #def test_write(self):
        # write to the db file
        #id is 1, all over fields are test_client

    def test_read(self):
        #db = database.database()
        clients = self.test_db.read(self.test_client)

        self.assertIn(self.test_client, clients)        
        #self.assertEqual(result, " ")

if __name__ == '__main__':
    unittest.main()