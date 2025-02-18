#!/var/ossec/framework/python/bin/python3

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
logger = logging.getLogger("fim-report")
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

def getSyscheck(agent_id, limit=1000):
    file_list = []
    file_limit = limit
    file_total = 0
    # API processing
    logger.debug("Obtaining the first %d files", file_limit)
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscheck/" + agent_id + "?wait_for_complete=true&limit=" + str(file_limit) 
    agent_package_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_package_request.content.decode('utf-8'))
    # First check and validating total ammount of files
    if agent_package_request.status_code != 200:
        logger.error("There were errors getting fim information")
        exit(6)
    else:
        #logger.debug(r)
        # Adding files to the list
        for file in r['data']['affected_items']:
            file_list.append(file)
        
        # Setting the total amount of files
        if file_total == 0 and int(r['data']['total_affected_items']) > file_limit:
            file_total = int(r['data']['total_affected_items'])
        
        # Processing all the file list
        while len(file_list) < file_total:
            # API processing
            logger.debug("Obtaining next %d files of %d", file_limit, file_total)
            msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
            msg_url = manager_url + "/syscheck/" + agent_id + "?wait_for_complete=true&limit=" + str(file_limit) + "&offset=" + str(len(file_list)) 
            agent_package_request = requests.get(msg_url, headers=msg_headers, verify=False)
            r = json.loads(agent_package_request.content.decode('utf-8'))
            if agent_package_request.status_code != 200:
                logger.error("There were errors getting fim information")
                exit(6)
            else:
                for file in r['data']['affected_items']:
                    file_list.append(file)
                logger.debug("Current file count %d out of %d", len(file_list), file_total)
        
        # Returning the values
        logger.debug("Finish obtaining files")
        return file_list        
            
        
def setSyscheck(fim_data, agent_id, location, SOCKET_ADDR):
    for data in fim_data:
        data["agent_id"]= agent_id
        string = '1:{0}->syscheck:{1}'.format(location, json.dumps(data))
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
    script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
    config_filename = str(os.path.join(script_dir, "syscollector-report.conf"))
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
        logger.debug("Error connecting to the API, exiting")
        exit(1)
    else:
        getAgentList()
        for agent in agent_list:
            if agent["id"] != '000':
                agent["syscheck"] = getSyscheck(agent["id"], 1000)
                setSyscheck(agent["syscheck"], agent["id"], 'wazuh-manager', SOCKET_ADDR)