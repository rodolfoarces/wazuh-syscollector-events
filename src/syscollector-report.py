#!/usr/bin/env python3

# Requirements
import sys
import requests
import json
import logging
import time
import configparser
import os.path
from socket import AF_UNIX, SOCK_DGRAM, socket

# Additional configurations
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

## Logging options
# https://docs.python.org/3/howto/logging-cookbook.html#logging-cookbook
# create file handler which logs even debug messages
logger = logging.getLogger("syscollector-report")
logger.setLevel(logging.DEBUG)
fh = logging.StreamHandler()
fh.setLevel(logging.DEBUG)
fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(fh_formatter)
logger.addHandler(fh)

def apiAuthenticate(manager_url,username, password):
    auth_endpoint = manager_url + "/security/user/authenticate"
    logger.debug("Starting authentication process")
    # api-endpoint
    auth_request = requests.get(auth_endpoint, auth=(username, password), verify=False)
    r = auth_request.content.decode("utf-8")
    auth_response = json.loads(r)
    try:
        return auth_response["data"]["token"]
    except KeyError:
        # "title": "Unauthorized", "detail": "Invalid credentials"
        if auth_response["title"] == "Unauthorized":
            logger.error("Authentication error")
            return None

def getAgentList():
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/agents?wait_for_complete=true" 
    agent_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_request.content.decode('utf-8'))
    # Check
    if agent_request.status_code != 200:
        logger.error("There were errors getting the agent list")
        exit(2)
    
    if r['data']['total_affected_items'] <= 1:
        logger.debug("No agents")
        exit(3)
    else:
        for agent in r['data']['affected_items']: 
            agent_list.append(agent)

def getAgentHardware(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/hardware?wait_for_complete=true" 
    agent_hardware_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_hardware_request.content.decode('utf-8'))
    # Check
    if agent_hardware_request.status_code != 200:
        logger.error("There were errors getting the agent hardware")
        exit(4)
    else:
        logger.debug(r)
        return r['data']['affected_items']
        

def getAgentProcesses(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/processes?wait_for_complete=true" 
    agent_process_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_process_request.content.decode('utf-8'))
    # Check
    if agent_process_request.status_code != 200:
        logger.error("There were errors getting the agent processes")
        exit(5)
    else:
        logger.debug(r)
        return r['data']['affected_items']

def getAgentOS(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/os?wait_for_complete=true" 
    agent_os_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_os_request.content.decode('utf-8'))
    # Check
    if agent_os_request.status_code != 200:
        logger.error("There were errors getting the agent os information")
        exit(6)
    else:
        logger.debug(r)
        return r['data']['affected_items']

def getAgentNetifaces(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/netiface?wait_for_complete=true" 
    agent_iface_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_iface_request.content.decode('utf-8'))
    # Check
    if agent_iface_request.status_code != 200:
        logger.error("There were errors getting the agent network interfaces information")
        exit(6)
    else:
        logger.debug(r)
        return r['data']['affected_items']

def getAgentNetaddr(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/netaddr?wait_for_complete=true" 
    agent_netaddr_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_netaddr_request.content.decode('utf-8'))
    # Check
    if agent_netaddr_request.status_code != 200:
        logger.error("There were errors getting the agent network address information")
        exit(6)
    else:
        logger.debug(r)
        return r['data']['affected_items']

def getAgentHotfixes(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/hotfixes?wait_for_complete=true" 
    agent_hotfix_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_hotfix_request.content.decode('utf-8'))
    # Check
    if agent_hotfix_request.status_code != 200:
        logger.error("There were errors getting the agent hotfixes information")
        exit(6)
    else:
        logger.debug(r)
        return r['data']['affected_items']

def getAgentProto(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/netproto?wait_for_complete=true" 
    agent_netproto_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_netproto_request.content.decode('utf-8'))
    # Check
    if agent_netproto_request.status_code != 200:
        logger.error("There were errors getting the agent network protocol information")
        exit(6)
    else:
        logger.debug(r)
        return r['data']['affected_items']

def getAgentPackages(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/packages?wait_for_complete=true" 
    agent_package_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_package_request.content.decode('utf-8'))
    # Check
    if agent_package_request.status_code != 200:
        logger.error("There were errors getting the agent packages information")
        exit(6)
    else:
        logger.debug(r)
        return r['data']['affected_items']

def getAgentPorts(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/ports?wait_for_complete=true" 
    agent_ports_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_ports_request.content.decode('utf-8'))
    # Check
    if agent_ports_request.status_code != 200:
        logger.error("There were errors getting the agent network ports information")
        exit(6)
    else:
        logger.debug(r)
        return r['data']['affected_items']

# Post Actions
def setHardware(hardware_data, location , SOCKET_ADDR):
    string = '1:{0}->syscollector:{1}'.format(location, json.dumps(hardware_data))
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
        logger.debug(string)
    except FileNotFoundError:
        logger.debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
        exit(4)

def setProcess(process_data, location , SOCKET_ADDR):
    count = 0
    for process in process_data:
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(process))
        try:
            sock = socket(AF_UNIX, SOCK_DGRAM)
            sock.connect(SOCKET_ADDR)
            sock.send(string.encode())
            sock.close()
            logger.debug(string)
        except FileNotFoundError:
            logger.debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
            exit(4)

def setOS(os_data, location, SOCKET_ADDR):
    string = '1:{0}->syscollector:{1}'.format(location, json.dumps(os_data))
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
        logger.debug(string)
    except FileNotFoundError:
        logger.debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
        exit(4)

def setNetIface(netiface_data, location, SOCKET_ADDR):
    for netiface in netiface_data:
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(netiface))
        try:
            sock = socket(AF_UNIX, SOCK_DGRAM)
            sock.connect(SOCKET_ADDR)
            sock.send(string.encode())
            sock.close()
            logger.debug(string)
        except FileNotFoundError:
            logger.debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
            exit(4)

def setNetAddr(netaddr_data, location, SOCKET_ADDR):
    for netiface in netaddr_data:
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(netiface))
        try:
            sock = socket(AF_UNIX, SOCK_DGRAM)
            sock.connect(SOCKET_ADDR)
            sock.send(string.encode())
            sock.close()
            logger.debug(string)
        except FileNotFoundError:
            logger.debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
            exit(4)

def setProto(proto_data, location, SOCKET_ADDR):
    for protocol in proto_data:
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(protocol))
        try:
            sock = socket(AF_UNIX, SOCK_DGRAM)
            sock.connect(SOCKET_ADDR)
            sock.send(string.encode())
            sock.close()
            logger.debug(string)
        except FileNotFoundError:
            logger.debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
            exit(4)
            
def setPackage(package_data, location, SOCKET_ADDR):
    for package in package_data:
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(package))
        try:
            sock = socket(AF_UNIX, SOCK_DGRAM)
            sock.connect(SOCKET_ADDR)
            sock.send(string.encode())
            sock.close()
            logger.debug(string)
        except FileNotFoundError:
            logger.debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
            exit(4)

def setPort(port_data, location, SOCKET_ADDR):
    for port in port_data:
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(port))
        try:
            sock = socket(AF_UNIX, SOCK_DGRAM)
            sock.connect(SOCKET_ADDR)
            sock.send(string.encode())
            sock.close()
            logger.debug(string)
        except FileNotFoundError:
            logger.debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
            exit(4)

def setHotfix(hotfix_data, location, SOCKET_ADDR):
    for hotfix in hotfix_data:
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(hotfix))
        try:
            sock = socket(AF_UNIX, SOCK_DGRAM)
            sock.connect(SOCKET_ADDR)
            sock.send(string.encode())
            sock.close()
            logger.debug(string)
        except FileNotFoundError:
            logger.debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
            exit(4)   
    
if __name__ == "__main__":
    # Initial values
    token = None
    manager_username = "wazuh"
    manager_password = "wazuh"
    manager_host = "localhost"
    manager_api_port = "55000"
    manager_url = "https://" + manager_host + ":" + manager_api_port
    SOCKET_ADDR = f'/var/ossec/queue/sockets/queue'
    
    # Configurations
    config_filename = "syscollector-report.conf"
    # Load data from configuration file
    if os.path.isfile(config_filename):
        logger.debug("Opening configuration file")
        config = configparser.ConfigParser()
        config.read(config_filename)
        # Wazuh manager connection
        manager_username = config.get('manager', 'manager_username')
        manager_password = config.get('manager', 'manager_password')
        manager_host =  config.get('manager', 'manager_host')
        manager_api_port =  config.get('manager', 'manager_api_port')
        manager_url = "https://" + manager_host + ":" + manager_api_port
    else:
        logger.debug("Error opening configuration file, taking default values")
    
    #Initial data structure
    agent_list = []

    # Connect to API
    token = apiAuthenticate(manager_url, manager_username, manager_password)
    if token == None:
        logger.debug("Error coonecting, exiting")
        exit(1)
    else:
        getAgentList()
        for agent in agent_list:
            agent["hardware"] = getAgentHardware(agent["id"])
            setHardware(agent["hardware"][0], 'wazuh-manager', SOCKET_ADDR)
            agent["processes"] = getAgentProcesses(agent["id"])
            setProcess(agent["processes"],'wazuh-manager', SOCKET_ADDR)
            agent["os"] = getAgentOS(agent["id"])
            setOS(agent["os"][0], 'wazuh-manager', SOCKET_ADDR)
            agent["netiface"] = getAgentNetifaces(agent["id"])
            setNetIface(agent["netiface"], 'wazuh-manager', SOCKET_ADDR)
            agent["netaddr"] = getAgentNetaddr(agent["id"])
            setNetAddr(agent["netaddr"], 'wazuh-manager', SOCKET_ADDR)
            # TO-DO, validate with os content present
            if 'windows' in agent["os"][0]["os"]["platform"] or 'Microsoft' in agent["os"][0]["os"]["name"]  : 
                agent["hotfix"] = getAgentHotfixes(agent["id"])
                setHotfix(agent["hotfix"], 'wazuh-manager', SOCKET_ADDR)
            else:
                logger.debug("Excluding hotfixes, it's not a Microsoft Windows endpoint")
            agent["proto"] = getAgentProto(agent["id"])
            setProto(agent["proto"], 'wazuh-manager', SOCKET_ADDR)
            agent["packages"] = getAgentPackages(agent["id"])
            setPackage(agent["packages"], 'wazuh-manager', SOCKET_ADDR)
            agent["ports"] = getAgentPorts(agent["id"])
            setPort(agent["ports"] , 'wazuh-manager', SOCKET_ADDR)
        #print(agent_list)
