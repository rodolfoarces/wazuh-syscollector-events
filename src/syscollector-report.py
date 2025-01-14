#!/usr/bin/env python3

# Requirements
import sys
import requests
import json
import logging
import time
import configparser
import os.path
from requests.auth import HTTPBasicAuth

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
def setHardware(hardware_data):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    hardware_content = { "cpu": { "cores": hardware_data["cpu"]["cores"], 
                        "mhz": hardware_data["cpu"]["mhz"], 
                        "name": hardware_data["cpu"]["name"]},
                        "ram": { "free": hardware_data["ram"]["free"], 
                        "total": hardware_data["ram"]["total"], 
                        "usage": hardware_data["ram"]["usage"]},
                        "agent_id": hardware_data["agent_id"],
                        "board_serial": hardware_data["board_serial"],
                        "scan": { "id": hardware_data["scan"]["id"], 
                        "time": hardware_data["scan"]["time"]}
                        }
    msg_data = { "events": [ str(hardware_content) ] }
    msg_url = manager_url + "/events?wait_for_complete=true" 
    forward_request = requests.post(msg_url, json=msg_data, headers=msg_headers, verify=False)
    r = json.loads(forward_request.content.decode('utf-8'))
    # Check 
    if forward_request.status_code != 200:
        logger.error("There were errors sending the hardware logs")
        logger.debug(r)
    else:
        logger.debug(r)

def setProcess(process_data_list):
    for process_data in process_data_list:
        msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
        process_content = { "size": process_data["size"],
                           "utime": process_data["utime"],
                           "ppid": process_data["ppid"],
                           "name": process_data["name"],
                           "vm_size": process_data["vm_size"],
                           "session": process_data["session"],
                           "start_time": process_data["start_time"],
                           "priority": process_data["priority"],
                           "cmd": process_data["cmd"],
                           "stime": process_data["stime"],
                           "pid": process_data["pid"],
                           "nlwp": process_data["nlwp"],
                           "agent_id": process_data["agent_id"],
                            "scan": { "id": process_data["scan"]["id"], 
                            "time": process_data["scan"]["time"]}
                            }
        msg_data = { "events": [ str(process_content) ] }
        msg_url = manager_url + "/events?wait_for_complete=true" 
        forward_request = requests.post(msg_url, json=msg_data, headers=msg_headers, verify=False)
        r = json.loads(forward_request.content.decode('utf-8'))
        # Check 
        if forward_request.status_code != 200:
            logger.error("There were errors sending the process events")
            logger.debug(r)
        else:
            logger.debug(r)
            
if __name__ == "__main__":
    # Initial values
    token = None
    manager_username = "wazuh"
    manager_password = "wazuh"
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
            setHardware(agent["hardware"][0])
            agent["processes"] = getAgentProcesses(agent["id"])
            setProcess(agent["processes"])
            #agent["os"] = getAgentOS(agent["id"])
            #agent["netiface"] = getAgentNetifaces(agent["id"])
            #agent["netaddr"] = getAgentNetaddr(agent["id"])
            # TO-DO, validate with os content present
            #if agent["os"]["os"]["name"] == "Windows":
            #    agent["hotfix"] = getAgentHotfixes(agent["id"])
            #agent["proto"] = getAgentProto(agent["id"])
            #agent["packages"] = getAgentPackages(agent["id"])
            #agent["ports"] = getAgentPorts(agent["id"])
        #print(agent_list)
