#! /usr/bin/env python

"""firewall.py: """

# imports
import time

__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2021, Salus Technologies"
__credits__ = ["Jason M. Pittman", "Kyle Wiseman"]
__license__ = "GPLv3"
__version__ = "1.0.0 beta"
__maintainer__ = "Jason M. Pittman"
__email__ = "jason@jasonmpittman.com"
__status__ = "Development"


#import iptc
import os
import sys
for xtdir in ["/usr/lib64/xtables/", "/lib/xtables", "/usr/lib/xtables", "/usr/local/lib/xtables"]:
    if os.path.isdir(xtdir):
        os.environ['XTABLES_LIBDIR'] = xtdir
        break
try:
    import iptc
except:
    sys.exit("python-iptables isn't installed.")

import subprocess
from subprocess import check_output
import configparser

class FirewallHandler():
    _table = ''

    def __init__(self):
        self._table = iptc.Table(iptc.Table.FILTER)

    def get_chains(self): # tested on 8/31 need error handling
        """Queries local IPTables for list of active, non-default chains
        
        Args: 

        Returns:
            chains (list): The return value is the list collection of active, non-default chains
        
        """
        chains = [ ]

        for chain in self._table.chains:
            chains.append(chain.name)

        return chains

    def get_rules_in_chain(self, chain): #this causes an exception...maybe remove method
        """Queries local IPTables for list of rules in specified chain
        
        Args: 
            chain (str):

        Returns:
            rules (list): The return value is the list collection of rules in specified chain
        
        """
        rules = [ ]

        try:
            for active_chain in self._table.chains:
                if active_chain.name == chain:
                    for rule in active_chain.rules:
                        rules.append(rule.name)
        except Exception as ex:
            print(str(ex)) # add logging
        
        return rules

    def are_default_rules_present(self): #done 5/9/22 ; 6/18/22 need to reconfirm this later
        is_present = False

        try:
            chain = iptc.easy.dump_chain('filter', 'INPUT', ipv6=False)
            
            for i in range(0,len(chain)):
                if chain[i]['comment']['comment'] == "default racs rule to accept loopback traffic":
                    is_present = True
                else:
                    is_present = False
        except Exception as e:
            print(str(e))
        
        return is_present
        

    def set_default_rules(self): # done 5/9/22 ; 6/18/22 added bidirectional established rules
        """Sets a list of default rules to allow traffic on our loopback as well as rac traffic
        
        Args: 

        Returns:
            
        
        """
        # allow traffic across loopback
        subprocess.run(["iptables -A INPUT -i lo -j ACCEPT"], shell=True)

        # allow traffic bidirectional once connection established
        subprocess.run(["iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"], shell=True)
        subprocess.run(["iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT"], shell=True)

        # set user defined exceptions here (e.g., web server)

    def set_user_rules(self, services): #tested on 9/18 need error handling
        """Sets a list of user defined services to accomodate public servers

        Args:
            services (list):
        
        Returns:

        """
        config = configparser.ConfigParser()
        config.read(services)

        for section in config.sections():
            rule = iptc.Rule()
            if config.get(section, 'src') != '':
                rule.src = config.get(section, 'src')
            if config.get(section, 'dst') != '':
                rule.dst = config.get(section, 'dst')
            rule.in_interface = config.get(section, 'interface')
            rule.protocol = config.get(section, 'protocol')
            rule.target = rule.create_target(config.get(section, 'target'))
            match = rule.create_match("comment")
            match.comment = "user defined rule"
            match = rule.create_match(config.get(section, 'protocol'))
            match.dport = config.get(section, 'port') 
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), config.get(section, 'chain'))
            chain.insert_rule(rule)

    def is_rac_chain_present(self, chain): #tested on 9/22
        """
            Args:
                chain(str): 

            Returns:
                
        """
        output = check_output(["iptables", "-L"])
        
        if chain in str(output):
            return True
        else:
            return False

    def add_knock_chains(self, client, ports):
        """
            Args:
                chain(str): The unique id of the client
                ports(list): The list of knock ports
            
            Returns:

        """
        table = iptc.Table(iptc.Table.FILTER)
        
        # we client the client id to 10 char because of iptables limitation on chain name
        c = client[1:10]
        
        #need to flush rules if chain exists and ensure __add runs      
        
        try:
            # racs chain to hold rac chains
            self.__build_racs_chain()

            # chain for first rac
            self.__build_RAC1_chain(table, c, ports) #this works but needs knock tested 5/20

            # chain for second rac
            self.__build_RAC2_chain(table, c, ports) #could just pass ports[1] here and don't know if we need table

            # chain for third rac
            self.__build_RAC3_chain(table, c, ports)

            # chain for racs passed to ssh
            self.__build_SSH_chain(table, c, "22") 

            # add our knock state chains to the main INPUT chain
            self.__build_input_chain(c)
        except Exception as e:
            print('Error from FirewallHandler at in add_knock_chains as ' + str(e))
    
    def __build_racs_chain(self):
        if not self.is_rac_chain_present('RACS'):
            print('RACS chain not present...creating it now')
            try:
                subprocess.run(["iptables -N RACS"], shell=True)
            except Exception as e:
                print('Error from FirewallHandler in __build_racs_chain as ' + str(e))
        else:
            print('RACS chain present')
    
    def __build_RAC1_chain(self, table, c, ports): # this works 5/22 but needs refactoring
        if not self.is_rac_chain_present('RAC1_' + c):
            print('RAC1 chain not present...creating it now')
            try:
                #create the chain
                subprocess.run(["iptables -N RAC1_" + c], shell=True)

                # flag the correct first rac attempt
                subprocess.run(["iptables -A RAC1_" + c + " -p tcp --dport " + str(ports[0]) + " -m recent --name " + "AUTH1_" + c + " --set -j DROP"], shell=True)

                # drop all other traffic
                subprocess.run(["iptables -A RAC1_" + c + " -j DROP"], shell=True) 
            except Exception as e:
                print('Error from FirewallHandler in __build_RAC1_chain as ' + str(e))
        else:
            print('RAC1 chain present...')
            try:
                # flag the correct first rac attempt
                subprocess.run(["iptables -A RAC1_" + c + " -p tcp --dport " + str(ports[0]) + " -m recent --name " + "AUTH1_" + c + " --set -j DROP"], shell=True)

                # drop all other traffic
                subprocess.run(["iptables -A RAC1_" + c + " -j DROP"], shell=True)
            except Exception as e:
                print('Error from FirewallHandler in __build_RAC1_chain as ' + str(e))

    def __build_RAC2_chain(self, table, c, ports): # this works 5/22 but needs refactoring
        if not self.is_rac_chain_present('RAC2_' + c):
            print('RAC2 chain not present...creating it now')
            try:
                #create the chain
                subprocess.run(["iptables -N RAC2_" + c], shell=True)

                # clear the prior flag
                subprocess.run(["iptables -A RAC2_" + c + " -m recent --name AUTH1_" + c + " --remove"], shell=True)
                
                # flag the correct second rac attempt
                subprocess.run(["iptables -A RAC2_" + c + " -p tcp --dport " + str(ports[1]) + " -m recent --name " + "AUTH2_" + c + " --set -j DROP"], shell=True)

                # send traffic back to RAC1
                subprocess.run(["iptables -A RAC2_" + c + " -j RAC1_" + c], shell=True)
            except Exception as e:
                print('Error from FirewallHandler in __build_RAC2_chain as ' + str(e))
        else:
            print('RAC2 chain present...')
            try:
                # clear the prior flag
                subprocess.run(["iptables -A RAC2_" + c + " -m recent --name AUTH1_" + c + " --remove"], shell=True)
                
                # flag the correct second rac attempt
                subprocess.run(["iptables -A RAC2_" + c + " -p tcp --dport " + str(ports[1]) + " -m recent --name " + "AUTH2_" + c + " --set -j DROP"], shell=True)

                # send traffic back to RAC1
                subprocess.run(["iptables -A RAC2_" + c + " -j RAC1_" + c], shell=True) 
            except Exception as e:
                print('Error from FirewallHandler in __build_RAC2_chain as ' + str(e))

    def __build_RAC3_chain(self, table, c, ports): # this works 5/22 but needs refactoring
        if not self.is_rac_chain_present('RAC3_' + c):
            print('RAC3 chain not present...creating it now')
            try:
                #create the chain
                subprocess.run(["iptables -N RAC3_" + c], shell=True)

                # clear the prior flag
                subprocess.run(["iptables -A RAC3_" + c + " -m recent --name AUTH2_" + c + " --remove"], shell=True)
                
                # flag the correct third rac attempt
                subprocess.run(["iptables -A RAC3_" + c + " -p tcp --dport " + str(ports[2]) + " -m recent --name " + "AUTH3_" + c + " --set -j DROP"], shell=True)

                # send traffic back to RAC1
                subprocess.run(["iptables -A RAC3_" + c + " -j RAC1_" + c], shell=True) 
            except Exception as e:
                print('Error from FirewallHandler in __build_RAC3_chain as ' + str(e))
        else:
            print('RAC3 chain present...')
            try:
                # clear the prior flag
                subprocess.run(["iptables -A RAC3_" + c + " -m recent --name AUTH2_" + c + " --remove"], shell=True)
                
                # flag the correct third rac attempt
                subprocess.run(["iptables -A RAC3_" + c + " -p tcp --dport " + str(ports[2]) + " -m recent --name " + "AUTH3_" + c + " --set -j DROP"], shell=True)

                # send traffic back to RAC1
                subprocess.run(["iptables -A RAC3_" + c + " -j RAC1_" + c], shell=True) 
            except Exception as e:
                print('Error from FirewallHandler in __build_RAC3_chain as ' + str(e))

    def __build_SSH_chain(self, table, c, ports): # don't need 'ports' here # this works 5/22 but needs refactoring
        if not self.is_rac_chain_present('SSH_' + c):
            print('SSH chain not present...creating it now')
            try:
                #create the chain
                subprocess.run(["iptables -N SSH_" + c], shell=True)

                # clear the prior flag
                subprocess.run(["iptables -A SSH_" + c + " -m recent --name AUTH3_" + c + " --remove"], shell=True)

                # open ssh after racs               
                subprocess.run(["iptables -A SSH_" + c + " -p tcp --dport 22 -j ACCEPT"], shell=True)

                # send traffic back to RAC1
                subprocess.run(["iptables -A SSH_" + c + " -j RAC1_" + c], shell=True)
            except Exception as e:
                print('Error from FirewallHandler in __build_SSH_chain as ' + str(e))
        else:
            print('SSH chain present...')
            try:
                # clear the prior flag
                subprocess.run(["iptables -A SSH_" + c + " -m recent --name AUTH3_" + c + " --remove"], shell=True)

                # open ssh after racs               
                subprocess.run(["iptables -A SSH_" + c + " -p tcp --dport 22 -j ACCEPT"], shell=True)

                # send traffic back to RAC1
                subprocess.run(["iptables -A SSH_" + c + " -j RAC1_" + c], shell=True)
            except Exception as e:
                print('Error from FirewallHandler in __build_SSH_chain as ' + str(e))

    def __build_input_chain(self, c): 
        try:
            print("Adding RACS to INPUT")
            subprocess.run(["iptables -A INPUT -j RACS"], shell=True)

            print('Adding RAC chains to RACS chain...')
            # 
            subprocess.run(["iptables -A RACS -m recent --reap --rcheck --seconds 30 --name AUTH3_" + c + " -j SSH_" + c], shell=True)
            # 
            subprocess.run(["iptables -A RACS -m recent --reap --rcheck --seconds 10 --name AUTH2_" + c + " -j RAC3_" + c], shell=True)    
            # 
            subprocess.run(["iptables -A RACS -m recent --reap --rcheck --seconds 10 --name AUTH1_" + c + " -j RAC2_" + c], shell=True)
            # 
            subprocess.run(["iptables -A RACS -j RAC1_" + c], shell=True)                
        except Exception as e:
            print('Error from FirewallHandler in __build_input_chain as ' + str(e))

    def remove_knock_chains(self, client): # tested on 9/18 needs error handling
        """
            Args:
                client(str):

            Returns:

        """
        table = iptc.Table(iptc.Table.FILTER)

        try: #if there's a problem with one, the rest fail to execute... #assume this works for now; build intelligence in v2

            table.delete_chain('RAC1_' + client)
            table.delete_chain('RAC2_' + client)
            table.delete_chain('RAC3_' + client)
            table.delete_chain('SSH_' + client)
        
        except Exception as e:
            #print(e(str)) # need to implement logging here
            print('Error from FirewallHandler in remove_knock_chain as ' + str(e))