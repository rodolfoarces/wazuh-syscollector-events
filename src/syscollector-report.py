#!/usr/bin/env python3

# Requirements
import sys
import requests
import json
import logging
import time
import configparser
import os.path
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

## Logging options
# https://docs.python.org/3/howto/logging-cookbook.html#logging-cookbook
# create file handler which logs even debug messages
logger = logging.getLogger("syscollect")
logger.setLevel(logging.DEBUG)
fh = logging.StreamHandler()
fh.setLevel(logging.DEBUG)
fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(fh_formatter)
logger.addHandler(fh)

# Variables
token = None
username = "wazuh"
password = "wazuh"
manager_host = "localhost"
manager_api_port = "55000"
manager_url = "https://" + manager_host + ":" + manager_api_port

# Configurations
config_filename = "syscollector-report.conf"

# Load data from configuration file
if os.path.isfile(config_filename):
	logger.debug("Opening configuration file")
	config = configparser.ConfigParser()
	config.read(config_filename)
	username = config.get('global', 'username')
	password = config.get('global', 'password')
	manager_host =  config.get('global', 'manager_host')
	manager_api_port =  config.get('global', 'manager_api_port')
	manager_url = "https://" + manager_host + ":" + manager_api_port
else:
	logger.debug("Error opening configuration file, taking default values")

agent_list = []

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
        for agents in r['data']['affected_items']: 
            agent_list.append(agents['id'])

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
    logger.debug(r)

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
    logger.debug(r)

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
    logger.debug(r)

def isWindowsOS(agent_id):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/os?wait_for_complete=true" 
    agent_os_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_os_request.content.decode('utf-8'))
    # Check
    if agent_os_request.status_code != 200:
        logger.error("There were errors getting the agent os information")
        exit(6)
    os_name = r['data']['affected_items'][0]['os']['name']
    return 'Windows' in os_name

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
    logger.debug(r)

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
    logger.debug(r)

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
    logger.debug(r)

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
    logger.debug(r)

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
    logger.debug(r)

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

if __name__ == "__main__":
    token = apiAuthenticate(manager_url, username, password)
    if token == None:
        logger.debug("Error, exiting")
        exit(1)
    else:
        getAgentList()
        for agent in agent_list:
            getAgentHardware(agent)
            getAgentProcesses(agent)
            getAgentOS(agent)
            getAgentNetifaces(agent)
            getAgentNetaddr(agent)
            if isWindowsOS(agent):
                getAgentHotfixes(agent)
                logger.debug("The OS is Windows")              
            else:
                logger.debug("The OS is not Windows")
            getAgentHotfixes(agent)
            getAgentProto(agent)
            getAgentPackages(agent)
            getAgentPorts(agent)
