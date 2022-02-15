#! /usr/bin/env python

"""kommen.py: """

# imports
import urllib.request
import argparse
import configparser
import json

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"


"""

    Core methods to interact with the Kommen secure remote access service
    
    Attributes:

    Functions:
        add_client() --
        delete_client() --
        reset_client() -- 
        rekey_client() --
        list_active_chains() --
        list_clients() --

"""    

config = configparser.ConfigParser()
config.read('server.ini')
__server = config['service']['url']
__port = config['service']['port']
__url = 'http://' + __server + ':' + __port

def add_client(rac):
    if rac == "empty_string":
        print("Adding a new client with a randomized rac")
        with urllib.request.urlopen(__url + '/add_client') as get:
            print(get.read(300))
    else:
        print("Adding a new client with rac: " + rac)
        with urllib.request.urlopen(__url + '/add_client/' + rac) as get:
            print(get.read(300))
    
def delete_client(client_id):
    if client_id == "empty_string":
        print("You must supply a client id to delete")
    else:
        print("We would delete client :" + client_id)
        with urllib.request.urlopen(__url + '/delete_client/' + client_id) as get:
            print(get.read(300))

def reset_client(client_id):
    if client_id == "empty string":
        with urllib.request.urlopen(__url + '/reset_client') as get: # we should have a confirmation prompt here so the sysadmin doesn't reset all clients by accident
            print(get.read(300))
    else:
        with urllib.request.urlopen(__url + '/reset_client/' + client_id) as get:
            print(get.read(300))

def rekey_client(client_id):
    if client_id == "empty string":
        print("Please provide a client to rekey")
        #with urllib.request.urlopen(__url + '/rekey_client') as get: # we should have a confirmation prompt here so the sysadmin doesn't reset all clients by accident
        #    print(get.read(300))
    else:
        with urllib.request.urlopen(__url + '/rekey_client/' + client_id) as get:
            print(get.read(300))

def list_clients( ):
    with urllib.request.urlopen(__url + '/list_clients') as get:
        clients = eval(get.read().decode('utf-8'))

        for client in clients:
            print(client['name'] + '\t' + str(client['status']))

def list_chains(client_id):
    if client_id == "empty string":
        with urllib.request.urlopen(__url + '/list_chains') as get:
            print(get.read())
    else:
        with urllib.request.urlopen(__url + '/list_chains/' + client_id) as get:
            print(get.read(300))

def disable_client(client_id):
    # feature: option to disable all clients
    if client_id == "empty string":
        print("Please provide a client name to disable")
    else:
        with urllib.request.urlopen(__url + '/disable_client/' + client_id) as get:
            print(get.read(300))

def enable_client(client_id):
    if client_id == "empty string":
        print("Please provide a client name to enable")
    else:
        with urllib.request.urlopen(__url + '/enable_client/' + client_id) as get:
            print(get.read(300))

def revoke_client(client_id):
    if client_id == "empty string":
        print("Please provide a client name to revoke")
    else:
        with urllib.request.urlopen(__url + '/revoke_client/' + client_id) as get:
            print(get.read(300))

parser = argparse.ArgumentParser(description="Interact with the kommen server")
parser.add_argument("-a", "--add_client", dest="add", nargs="?", const="empty_string", help="add a new client")
parser.add_argument("-d", "--delete_client", dest="delete", nargs="?", const="empty_string", help="delete the specified client")
parser.add_argument("-r", "--reset-client", dest="reset", nargs="?", const="empty_string", help="reset the specificied client")
parser.add_argument("-k", "--rekey-client", dest="rekey", nargs="?", const="empty_string", help="generate new keys for the specified client")
parser.add_argument("-l", "--list-clients", dest="list", nargs="?", const="empty_string", help="list the registered clients")
parser.add_argument("-c", "--list-chains", dest="chains", nargs="?", const="empty_string", help="list the current chains in the server")
parser.add_argument("-e", "--enable-client", dest="enable", nargs="?", const="empty_string", help="enable the specificed client")
parser.add_argument("-x", "--disable-client", dest="disable", nargs="?", const="empty_string", help="disable the specificed client")
parser.add_argument("-v", "--revoke-client", dest="revoke", nargs="?", const="empty_string", help="revoke the specificed client's asymmetric keypair")

args = parser.parse_args()

if args.add:
    add_client(args.add)
elif args.delete:
    delete_client(args.delete)
elif args.reset:
    reset_client(args.reset)
elif args.rekey:
    rekey_client(args.rekey)
elif args.list:
    list_clients( )
elif args.chains:
    list_chains(args.chains)
elif args.enable:
    enable_client(args.enable)
elif args.disable:
    disable_client(args.disable)
elif args.revoke:
    revoke_client(args.revoke)
else:
    print("This went wrong")   