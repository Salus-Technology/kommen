#! /usr/bin/env python

"""database.py: """

# imports
import os
import sqlite3
from sqlite3.dbapi2 import Error

from handlers import client

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

class DatabaseHandler:
    """

    Database methods to read and write to the Kommen db
    
    Attributes:

    Functions:
        connect() --
        disconnect() --
        read() --
        write() --
        update() --

    """

    __db_handle = " "
    __db_file = os.path.relpath("data/kommen.db")

    def __init__(self):
        # check if db exists; if not, create it
        self.connect()

    def connect(self):
        try:
            self.__db_handle = sqlite3.connect(self.__db_file)
        except Error as e:
            print("Error connecting to db: {0}".format(e)) # need to log this

    #def disconnect(self):

    def read(self):#, client=None):
        
        db = sqlite3.connect(self.__db_file)
        curs = db.cursor()
        sql = "SELECT * FROM client"

        curs.execute(sql)
        rows = [x for x in curs]
        cols = [x[0] for x in curs.description]

        client_list = []
        for row in rows:
            client = {}
            for prop, val in zip(cols, row):
                client[prop] = val
            client_list.append(client)

        db.close()

        return client_list

    def write(self, c: client):
        #add new client
        db = sqlite3.connect(self.__db_file)
        curs = db.cursor()
        # id, name, status, sym, pub, priv, client_id, count
        try:
            curs.execute("INSERT INTO client VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (None, c.client_name, c.client_status, c.client_symkey, c.client_pubkey, c.client_privkey, c.client_id, c.client_count)) 
        except Exception as e:
            print(str(e)) # need logging here
        finally:
            db.commit()
            db.close()

    def update(self, c: client, change):
        db = sqlite3.connect(self.__db_file)
        curs = db.cursor()
        # need a return so we know if this worked or not
        is_success = False
        #update existing client with change
        if change == "count":
            pass
        elif change == "rekey":
            try:
                curs.execute("UPDATE client SET pub_key = ?, priv_key = ? WHERE name = ? ", (c.client_pubkey, c.client_privkey, c.client_name,)) # change this to update keys
                db.commit()
                is_success = True
            except Exception as e:
                print("From database update method: " + str(e)) # need logging here
            finally:
                db.close()
        elif change == "disable":
            try:
                curs.execute("UPDATE client SET status = 0 WHERE name = ? ", (c.client_name,))
                db.commit()
                is_success = True
            except Exception as e:
                print("From database update method: " + str(e)) # need logging here
            finally:
                db.close()
        elif change == "enable":
            try:
                curs.execute("UPDATE client SET status = 1 WHERE name = ? ", (c.client_name,))
                db.commit()
                is_success = True
            except Exception as e:
                print("From database update method: " + str(e)) # need logging here
            finally:
                db.close()                

        return is_success

    def remove(self, client_id):
        db = sqlite3.connect(self.__db_file)
        curs = db.cursor()
        try:
            curs.execute("DELETE FROM client WHERE name = ? ", (client_id,))
            db.commit()
        except Exception as e:
            print(str(e)) # need logging here
        finally:
            db.close()
        

# id -- int pk
# name -- text sha256 hash identifier
# status -- 0 or 1 for active, inactive
# sym_key -- sha256 hash of clients symmetric key
# pub_key -- sha256 hash of clients public asymmetric key
# priv_key -- sha256 hash of clients private asymmetric key