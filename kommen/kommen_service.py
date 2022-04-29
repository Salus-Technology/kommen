#! /usr/bin/env python

"""kommen_service.py: """

# imports
from handlers.firewall import FirewallHandler
from flask import Flask, jsonify
from apscheduler.schedulers.background import BackgroundScheduler

import json
import sys
#sys.path.append('../handlers/')
from handlers import database
from handlers import client
from handlers import clients
from handlers import registration
from handlers import server

from kommen.handlers.remote_access_sequence import RemoteAccessCodeSequenceHandler

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"

#load list of clients, generating chains, etc.
def kommen_protocol():
    print("Protocol running...")

# need to add APScheduler here on [n] interval conditionally run this if interval is op_mode
#sched = BackgroundScheduler(daemon=True)
#sched.add_job(func=kommen_protocol, trigger='interval', seconds=1)
#sched.start()

app = Flask(__name__)
app.config["DEBUG"] = True # toss this into a kommen.config service cfg later

# we need to check if this is the first time the server has run
# if so we need to generate the server keys and get everything setup

list_of_clients = clients.ClientsHandler()

# https://networklore.com/start-task-with-flask/
# we need to set the default fw tables and chains the first time we run
# we should check to make sure those are in place whenever the service starts up (but not each cycle)?

@app.route("/")
def index():
    pass

@app.route("/initialize/", defaults={}, methods=['GET'])
def initialize():
    svr = server.ServerHandler()
    state = svr.initialize_server()

    return "<h1> Result from server initializaiton: " + str(state) + "</h1>"

@app.route("/server_status", defaults={}, methods=['GET'])
def server_status():
    pass

@app.route("/add_client", defaults={"rac": None}, methods=['GET'])
@app.route("/add_client/<rac>")
def add_client(rac):
    reg = registration.RegistrationHandler() # why did I do this here?

    if rac is None:
        # run registration logic here
        reg = registration.RegistrationHandler()
        list_of_clients.add_client(reg.register_client())
        
        #for c in list_of_clients:
        #    print(c.client_name)

        return "<h1> Added new client with client id: " +  list_of_clients.get_client() + "</h1>"
    else:
        # run registration with provided rac here
        return "<h1> Adding new client with rac: " + rac + "</h1>" # this needs finished

@app.route("/delete_client/<client_id>", methods=['GET']) #this works 9/11
def delete_client(client_id):
    reg = registration.RegistrationHandler()
    is_success = reg.delete_client(str(client_id))

    #if is_success is True: remove the client from list_of_clients
    if is_success is True:
        pass #do we call remove or just reload?

    return "<h1> Deleted " + client_id + " </h1>"

@app.route("/reset_client/<client_id>")
def reset_client(client_id):
    pass

@app.route("/rekey_client/<client_id>", methods=['GET']) #we use this to generate new keys but retain the name and client_id
def rekey_client(client_id): #this works 9/11
    result = "Empty result"

    load_clients()

    for client in list_of_clients:
              
        if client_id == client.client_name:
            reg = registration.RegistrationHandler()
            result = reg.rekey_client(client)

    #we need to (re)load clients to refresh the list after changing

    if result == True:
        return "<h1> Successfully rekeyed client " + client_id + "</h1>"
    else:
        return "<h1> Failed to rekey client " + client_id + "</h1>"        

@app.route("/list_clients", methods=['GET']) #this works 9/11
def list_clients( ):
    db = database.DatabaseHandler()
    clients = json.dumps(db.read())
    
    return clients

@app.route("/list_chains", defaults={"client_id": None})
@app.route("/list_chains/<client_id>")
def list_chains(client_id):
    fw = FirewallHandler()
    chains = fw.get_chains()
    #print(chains)

    return str(chains)

    #for chain in chains:
    #    print(chain)

    # def list_clients(self, client=None):
    #     db = database.database()
        
    #     if client is None:
    #         clients = db.read()
        
    #         for client in clients:
    #             print(client)
    #     else:
    #         client = db.read(client)
    #         print(client)

#@app.route("/enable_client", defaults={"client_id": None})
@app.route("/enable_client/<client_id>", methods=['GET']) #this works 9/11
def enable_client(client_id):
    result = False

    load_clients()

    for client in list_of_clients:          
        if client_id == client.client_name:    
            reg = registration.RegistrationHandler()
            result = reg.enable_client(client)

    if result == True:
        return "<h1> Successfully enabled client " + client_id + "</h1>"
    else:
        return "<h1> Failed to enable client " + client_id + "</h1>"

#@app.route("/disable_client", defaults={"client_id": None})
@app.route("/disable_client/<client_id>", methods=['GET']) #this works 9/11
def disable_client(client_id):
    result = False

    load_clients()

    for client in list_of_clients:          
        if client_id == client.client_name:
            reg = registration.RegistrationHandler()
            result = reg.disable_client(client)

    if result == True:
        return "<h1> Successfully disabled client " + client_id + "</h1>"
    else:
        return "<h1> Failed to disabled client " + client_id + "</h1>"

@app.route("/revoke_client/<client_id>", methods=['GET']) #this works 9/11
def revoke_client(client_id):
    result = False

    load_clients()

    for client in list_of_clients:          
        if client_id == client.client_name:
            reg = registration.RegistrationHandler()
            result = reg.revoke_client(client)
    
    if result == True:
        return "<h1> Successfully revoked client's keys" + client_id + "</h1>"
    else:
        return "<h1> Failed to revoked client's keys" + client_id + "</h1>"

def load_racs():
    racs = RemoteAccessCodeSequenceHandler()
    
    #generate a racs for each client
    #ensure it is unique or regenerate
    #send to the fw handler to be built as a chain

def load_clients( ): #this works 9/11
    # connect to db
    db = database.DatabaseHandler()

    temp_list = json.dumps(db.read())
    client_list = json.loads(temp_list)

    for c in client_list:
        new_client = client.ClientHandler()
        new_client.client_name = c['name']
        new_client.client_id = c['client_id']
        new_client.client_status = c['status']
        new_client.client_pubkey = c['pub_key']
        new_client.client_privkey = c['priv_key']
        new_client.client_symkey = c['sym_key']
        new_client.client_count = c['count']
        
        list_of_clients.add_client(new_client)


app.run()