

"""The TCP/IP Server component for Kommen"""

# standard library imports
import sys
import json
import socket
import multiprocessing
from collections import defaultdict
from xml.etree.ElementInclude import include

# third party imports

# local packages
from handlers import preamble
from handlers import firewall
from handlers import remote_access_sequence
from handlers import remote_access_code
#from kommen.handlers.firewall import FirewallHandler

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2022, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"


class KommenServer:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.fw = firewall.FirewallHandler()

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(1)

        # check if the default fw rules and etc. are in place
        if self.fw.are_default_rules_present():
            print('default rules found')
        else:
            self.fw.set_default_rules()

        while True:
            conn, address = self.server_socket.accept()
            
            process = multiprocessing.Process(target=self.handle, args=(conn, address))
            process.daemon = True
            process.start()


    def handle(self, connection, address):

        pre = preamble.PreambleHandler()
        
        racs = remote_access_sequence.RemoteAccessCodeSequenceHandler()
        
        #incoming_clients = {}
        ports = []

        try:
            print("Connected %r at %r", connection, address)

            while True:
                data = connection.recv(1024)
                
                #need to differentiate between a rac data payload, a preamble versus other
                if len(data) in range(131, 151):

                    #check if the client id is valid and the preamble is sanitized
                    is_preamble = pre.handle_premable(data)
                    
                    # if the preamble is good, we ack we process the racs into the firewall
                    if is_preamble:
                        connection.sendall("Preamble Acknowledged".encode())

                        try:
                            # set client iptables chain with rules here / increment counter + 1 before doing so

                            # check if client knock chains present in iptables

                            # we need to remove any existing knock chains for the client if present
                            #self.fw.remove_knock_chains(is_preamble[0]) 
                        
                            # generate client racs here [this works as of 5/11/22]
                            rac = remote_access_code.RemoteAccessCodeHandler(is_preamble[0])
                            
                            is_generated = racs.generate_racs(rac.generate_rac(int(is_preamble[1])))
                            print(is_generated)

                            ports = racs.get_racs()
                            print(ports)

                            #testing here can't create chain STATE0_802bae5a50989204908bd1208a09187308eed3987914e677979f6373733d7601: b'Invalid argument'
                            self.fw.add_knock_chains(is_preamble[0], ports) # we need to store incoming rac for each client until we get all three and then add the chains

                            # echo "iptables -D INPUT -s 192.168.1.100 -j DROP" | at @10pm at -t 202005111321.32

                            connection.sendall("RACS added to IPTables".encode())
                        except Exception as e:
                            print('Error at line 97 as ' + str(e))

                    else:
                        connection.sendall("There was an error with in the preamble")

                # I don't think we need this after all 5/10        
                #elif len(data) == 73:
                #    print('Incoming RAC detected...') # this needs to go out into a separate method
                    
                #    rac_payload = tuple(x for x in data.decode("utf-8").strip().split(','))
                                        
                #    if rac_payload[1] == '1':
                #        incoming_clients.setdefault(rac_payload[0], []).append(rac_payload[2])
                #    elif rac_payload[1] == '2':
                #        incoming_clients.setdefault(rac_payload[0], []).append(rac_payload[2])
                #    elif rac_payload[1] == '3':
                #        incoming_clients.setdefault(rac_payload[0], []).append(rac_payload[2])
                #    else:
                #        print('Sequence number out of bounds')
                    
                else:
                    print('Invalid preamble received') #placeholder...this applies to anything not a preamble or rac

                #this stops infinite looping
                if data.decode("utf-8").strip() == "":
                    print("Socket closed remotely")
                    break
                
                print("Received data %r", data)

                #if all of the above is good, we send ack for racs being ready || if not good, we send resend
                #connection.sendall(data)
                #print("Sent data")

        except Exception as e:
            print("An exception has occured: " + str(e))
        finally:
            connection.close()
 

if __name__ == "__main__":
    server = KommenServer("0.0.0.0", 5002)

    try:
        print("Listening")
        server.start()
    except Exception as e:
        print("Unexpected exception: " + str(e))
    finally:
        print("Shutting down")
        for process in multiprocessing.active_children():
            print("Shutting down process %r", process)
            process.terminate()
            process.join()
    
    print("All done")