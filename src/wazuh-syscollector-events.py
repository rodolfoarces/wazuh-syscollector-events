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
    # Variables
    hardware_list = []
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/hardware?wait_for_complete=true"
    agent_hardware_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_hardware_request.content.decode('utf-8'))
    # Check
    if agent_hardware_request.status_code != 200:
        logger.error("Get Hardware Information - There were errors getting the agent hardware")
        exit(4)
    else:
        # logger.debug(r)
        for hardware in r['data']['affected_items']:
            hardware_list.append(hardware)

    # Returning all collected data
    logger.info("Get Hardware Information - Returining %d events", len(hardware_list) )
    return hardware_list        
      
def getAgentProcesses(agent_id, limit=1000):
    # Variables
    process_list = []
    api_limit = limit
    process_total = 0
    
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/processes?wait_for_complete=true&limit=" + str(api_limit)
    agent_process_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_process_request.content.decode('utf-8'))
    # Check
    if agent_process_request.status_code != 200:
        logger.error("There were errors getting the agent processes")
        exit(5)
    else:
        for process in r['data']['affected_items']:
            process_list.append(process)
        
        if process_total == 0 and int(r['data']['total_affected_items']) > api_limit:
            process_total = int(r['data']['total_affected_items'])
            logger.info("Get Process Information - Obtaining %d events, in batches of %d events", int(r['data']['total_affected_items']), api_limit )
            
            # Iterate to obtain all events
            while len(process_list) < process_total:        
                # API processing
                msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
                msg_url = manager_url + "/syscollector/" + agent_id + "/process?wait_for_complete=true&limit=" + str(api_limit) + "&offset=" + str(len(process_list))
                agent_process_request = requests.get(msg_url, headers=msg_headers, verify=False)
                r = json.loads(agent_process_request.content.decode('utf-8'))
                # Check
                if agent_process_request.status_code != 200:
                    logger.error("Get Process Information - There were errors getting the agent hardware")
                    exit(4)
                else:
                    for process in r['data']['affected_items']:
                        process_list.append(process)
            
        elif int(r['data']['total_affected_items']) < api_limit:
            logger.info("Get Process Information - Obtained %d events", int(r['data']['total_affected_items']) )
    # Returning all data
    logger.info("Get Process Information - Returining %d events", len(process_list) )
    return process_list        
        
def getAgentOS(agent_id):
    # Variables
    os_list = []
    
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
        #logger.debug(r)
        for os in r['data']['affected_items']:
            os_list.append(os)
    return os_list

def getAgentNetifaces(agent_id, limit=1000):
    # Variables
    netiface_list = []
    api_limit = limit
    netiface_total = 0
    
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/netiface?wait_for_complete=true&limit=" + str(api_limit) 
    agent_iface_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_iface_request.content.decode('utf-8'))
    # Check
    if agent_iface_request.status_code != 200:
        logger.error("There were errors getting the agent network interfaces information")
        exit(6)
    else:
        #logger.debug(r)
        for netiface in  r['data']['affected_items']:
            netiface_list.append(netiface)
        if netiface_total == 0 and int(r['data']['total_affected_items']) > api_limit:
            netiface_total = int(r['data']['total_affected_items'])
            logger.info("Get Network Interface Information - Obtaining %d events, in batches of %d events", int(r['data']['total_affected_items']), api_limit )
            
            # Iterate to obtain all events
            while len(netiface_list) < netiface_total:        
                # API processing
                msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
                msg_url = manager_url + "/syscollector/" + agent_id + "/netiface?wait_for_complete=true&limit=" + str(api_limit) + "&offset=" + str(len(process_list))
                agent_iface_request = requests.get(msg_url, headers=msg_headers, verify=False)
                r = json.loads(agent_iface_request.content.decode('utf-8'))
                # Check
                if agent_iface_request.status_code != 200:
                    logger.error("Get Network Interface Information - There were errors getting the agent hardware")
                    exit(4)
                else:
                    for netiface in r['data']['affected_items']:
                        netiface_list.append(netiface)
            
        elif int(r['data']['total_affected_items']) < api_limit:
            logger.info("Get Network Interface Information - Obtained %d events", int(r['data']['total_affected_items']) )
    # Returning all data
    logger.info("Get Network Interface Information - Returining %d events", len(netiface_list) )
    return netiface_list        

def getAgentNetaddr(agent_id, limit=1000):
    # Variables
    netaddr_list = []
    api_limit = limit
    netaddr_total = 0
    
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
        #logger.debug(r)
        for netaddr in r['data']['affected_items']:
            netaddr_list.append(netaddr)
        
        if netaddr_total == 0 and int(r['data']['total_affected_items']) > api_limit:
            netaddr_total = int(r['data']['total_affected_items'])
            logger.info("Get Network Address Information - Obtaining %d events, in batches of %d events", int(r['data']['total_affected_items']), api_limit )
            
            # Iterate to obtain all events
            while len(netaddr_list) < netaddr_total:        
                # API processing
                msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
                msg_url = manager_url + "/syscollector/" + agent_id + "/netaddr?wait_for_complete=true&limit=" + str(api_limit) + "&offset=" + str(len(process_list))
                agent_netaddr_request = requests.get(msg_url, headers=msg_headers, verify=False)
                r = json.loads(agent_netaddr_request.content.decode('utf-8'))
                # Check
                if agent_netaddr_request.status_code != 200:
                    logger.error("Get Network Address Information - There were errors getting the agent hardware")
                    exit(4)
                else:
                    for netaddr in r['data']['affected_items']:
                        netaddr_list.append(netaddr)
            
        elif int(r['data']['total_affected_items']) < api_limit:
            logger.info("Get Network Address Information - Obtained %d events", int(r['data']['total_affected_items']) )
    # Returning all data
    logger.info("Get Network Address Information - Returining %d events", len(netaddr_list) )
    return netaddr_list

def getAgentHotfixes(agent_id, limit=1000):
    # Variables
    hotfixes_list = []
    api_limit = limit
    hotfixes_total = 0
    
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/hotfixes?wait_for_complete=true&limit=" + str(api_limit) 
    agent_hotfix_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_hotfix_request.content.decode('utf-8'))
    # Check
    if agent_hotfix_request.status_code != 200:
        logger.error("There were errors getting the agent hotfixes information")
        exit(6)
    else:
        #logger.debug(r)
        for hotfix in r['data']['affected_items']:
            hotfixes_list.append(hotfix)
            
        if hotfixes_total == 0 and int(r['data']['total_affected_items']) > api_limit:
            hotfixes_total = int(r['data']['total_affected_items'])
            logger.info("Get Hotfixes Information - Obtaining %d events, in batches of %d events", int(r['data']['total_affected_items']), api_limit )
            
            # Iterate to obtain all events
            while len(hotfixes_list) < hotfixes_total:        
                # API processing
                msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
                msg_url = manager_url + "/syscollector/" + agent_id + "/hotfixes?wait_for_complete=true&limit=" + str(api_limit) + "&offset=" + str(len(hotfixes_list))
                agent_hotfix_request = requests.get(msg_url, headers=msg_headers, verify=False)
                r = json.loads(agent_hotfix_request.content.decode('utf-8'))
                # Check
                if agent_hotfix_request.status_code != 200:
                    logger.error("Get Network Address Information - There were errors getting the agent hardware")
                    exit(4)
                else:
                    for hotfix in r['data']['affected_items']:
                        hotfixes_list.append(hotfix)
            
        elif int(r['data']['total_affected_items']) < api_limit:
            logger.info("Get Hotfixes Information - Obtained %d events", int(r['data']['total_affected_items']) )
    # Returning all data
    logger.info("Get Hotfixes Information - Returining %d events", len(hotfixes_list) )
    return hotfixes_list

def getAgentProto(agent_id, limit=1000):
    # Variables
    netproto_list = []
    api_limit = limit
    netproto_total = 0
    
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    msg_url = manager_url + "/syscollector/" + agent_id + "/netproto?wait_for_complete=true&limit=" + str(api_limit) 
    agent_netproto_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_netproto_request.content.decode('utf-8'))
    # Check
    if agent_netproto_request.status_code != 200:
        logger.error("There were errors getting the agent network protocol information")
        exit(6)
    else:
        #logger.debug(r)
        for netproto in r['data']['affected_items']:
            netproto_list.append(netproto)
        if netproto_total == 0 and int(r['data']['total_affected_items']) > api_limit:
            netproto_total = int(r['data']['total_affected_items'])
            logger.info("Get Network Protocol Information - Obtaining %d events, in batches of %d events", int(r['data']['total_affected_items']), api_limit )
            
            # Iterate to obtain all events
            while len(netproto_list) < netproto_total:        
                # API processing
                msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
                msg_url = manager_url + "/syscollector/" + agent_id + "/netproto?wait_for_complete=true&limit=" + str(api_limit) + "&offset=" + str(len(netproto_list))
                agent_netproto_request = requests.get(msg_url, headers=msg_headers, verify=False)
                r = json.loads(agent_netproto_request.content.decode('utf-8'))
                # Check
                if agent_netproto_request.status_code != 200:
                    logger.error("Get Network Address Information - There were errors getting the agent hardware")
                    exit(4)
                else:
                    for netproto in r['data']['affected_items']:
                        netproto_list.append(netproto)
            
        elif int(r['data']['total_affected_items']) < api_limit:
            logger.info("Get Network Address Information - Obtained %d events", int(r['data']['total_affected_items']) )
    # Returning all data
    logger.info("Get Network Address Information - Returining %d events", len(netproto_list) )
    return netproto_list
        

def getAgentPackages(agent_id, limit=1000):
    # Variables
    packages_list = []
    api_limit = limit
    packages_total = 0
    
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
        #logger.debug(r)
        for package in r['data']['affected_items']:
            packages_list.append(package)
        
        if packages_total == 0 and int(r['data']['total_affected_items']) > api_limit:
            packages_total = int(r['data']['total_affected_items'])
            logger.info("Get Packages Information - Obtaining %d events, in batches of %d events", int(r['data']['total_affected_items']), api_limit )
            
            # Iterate to obtain all events
            while len(packages_list) < packages_total:        
                # API processing
                msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
                msg_url = manager_url + "/syscollector/" + agent_id + "/packages?wait_for_complete=true&limit=" + str(api_limit) + "&offset=" + str(len(packages_list))
                agent_packages_request = requests.get(msg_url, headers=msg_headers, verify=False)
                r = json.loads(agent_packages_request.content.decode('utf-8'))
                # Check
                if agent_packages_request.status_code != 200:
                    logger.error("Get Packages Information - There were errors getting the agent hardware")
                    exit(4)
                else:
                    for package in r['data']['affected_items']:
                        packages_list.append(package) 
        elif int(r['data']['total_affected_items']) < api_limit:
            logger.info("Get Packages Information - Obtained %d events", int(r['data']['total_affected_items']) )
    # Returning all data
    logger.info("Get Packages Information - Returining %d events", len(packages_list) )
    return packages_list

def getAgentPorts(agent_id, limit=1000):
    # Variables
    netport_list = []
    api_limit = limit
    netport_total = 0
    
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
        #logger.debug(r)
        for netport in r['data']['affected_items']:
            netport_list.append(netport)
        
        if netport_total == 0 and int(r['data']['total_affected_items']) > api_limit:
            netport_total = int(r['data']['total_affected_items'])
            logger.info("Get Ports Information - Obtaining %d events, in batches of %d events", int(r['data']['total_affected_items']), api_limit )
            
            # Iterate to obtain all events
            while len(netport_list) < netport_total:        
                # API processing
                msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
                msg_url = manager_url + "/syscollector/" + agent_id + "/ports?wait_for_complete=true&limit=" + str(api_limit) + "&offset=" + str(len(netport_list))
                agent_ports_request = requests.get(msg_url, headers=msg_headers, verify=False)
                r = json.loads(agent_ports_request.content.decode('utf-8'))
                # Check
                if agent_ports_request.status_code != 200:
                    logger.error("Get Ports Information - There were errors getting the agent hardware")
                    exit(4)
                else:
                    for netport in r['data']['affected_items']:
                        netport_list.append(netport) 
        elif int(r['data']['total_affected_items']) < api_limit:
            logger.info("Get Ports Information - Obtained %d events", int(r['data']['total_affected_items']) )
    # Returning all data
    logger.info("Get Ports Information - Returining %d events", len(netport_list) )
    return netport_list

def socketSend (message):
    string = str(message)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
        logger.debug(string)
    except FileNotFoundError:
        logger.debug('# Error: Unable to open socket connection at %s, unable to send message:\n %s' % SOCKET_ADDR, message)
        exit(4)

# Post Actions
def setHardware(agent_data, hardware_data, location , SOCKET_ADDR):
    location = '[{0}] ({1}) {2}'.format(agent_data['id'], agent_data['name'], agent_data['ip'] if 'ip' in agent_data else 'any')
    location = location.replace('|', '||').replace(':', '|:')
    
    for hardware in hardware_data:
        hardware["endpoint"] = "hardware"
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(hardware))
        socketSend(string)

def setProcess(agent_data, process_data, location , SOCKET_ADDR):
    location = '[{0}] ({1}) {2}'.format(agent_data['id'], agent_data['name'], agent_data['ip'] if 'ip' in agent_data else 'any')
    location = location.replace('|', '||').replace(':', '|:')

    for process in process_data:
        process["endpoint"] = "processes"
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(process))
        socketSend(string)

def setOS(agent_data, os_data, location, SOCKET_ADDR):
    location = '[{0}] ({1}) {2}'.format(agent_data['id'], agent_data['name'], agent_data['ip'] if 'ip' in agent_data else 'any')
    location = location.replace('|', '||').replace(':', '|:')
    
    for os in os_data:
        os["endpoint"] = "os"
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(os))
        socketSend(string)

def setNetIface(agent_data, netiface_data, location, SOCKET_ADDR):
    location = '[{0}] ({1}) {2}'.format(agent_data['id'], agent_data['name'], agent_data['ip'] if 'ip' in agent_data else 'any')
    location = location.replace('|', '||').replace(':', '|:')
    
    for netiface in netiface_data:
        netiface["endpoint"] = "network_interfaces"
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(netiface))
        socketSend(string)

def setNetAddr(agent_data, netaddr_data, location, SOCKET_ADDR):
    location = '[{0}] ({1}) {2}'.format(agent_data['id'], agent_data['name'], agent_data['ip'] if 'ip' in agent_data else 'any')
    location = location.replace('|', '||').replace(':', '|:')
    
    for netaddr in netaddr_data:
        netaddr["endpoint"] = "network_addresses"
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(netaddr))
        socketSend(string)

def setProto(agent_data, proto_data, location, SOCKET_ADDR):
    location = '[{0}] ({1}) {2}'.format(agent_data['id'], agent_data['name'], agent_data['ip'] if 'ip' in agent_data else 'any')
    location = location.replace('|', '||').replace(':', '|:')
    
    for protocol in proto_data:
        protocol["endpoint"] = "network_protocols"
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(protocol))
        socketSend(string)
            
def setPackage(agent_data, package_data, location, SOCKET_ADDR):
    location = '[{0}] ({1}) {2}'.format(agent_data['id'], agent_data['name'], agent_data['ip'] if 'ip' in agent_data else 'any')
    location = location.replace('|', '||').replace(':', '|:')
    
    for package in package_data:
        package["endpoint"] = "packages"
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(package))
        socketSend(string)

def setPort(agent_data, port_data, location, SOCKET_ADDR):
    location = '[{0}] ({1}) {2}'.format(agent_data['id'], agent_data['name'], agent_data['ip'] if 'ip' in agent_data else 'any')
    location = location.replace('|', '||').replace(':', '|:')
    
    for port in port_data:
        port["endpoint"] = "network_ports"
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(port))
        socketSend(string)

def setHotfix(agent_data, hotfix_data, location, SOCKET_ADDR):
    location = '[{0}] ({1}) {2}'.format(agent_data['id'], agent_data['name'], agent_data['ip'] if 'ip' in agent_data else 'any')
    location = location.replace('|', '||').replace(':', '|:')
    
    for hotfix in hotfix_data:
        hotfix["endpoint"] = "hotfixes"
        string = '1:{0}->syscollector:{1}'.format(location, json.dumps(hotfix))
        socketSend(string)   
    
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
    config_filename = str(os.path.join(script_dir, "wazuh-syscollector-events.conf"))
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
                agent_data = { "id": agent["id"], "name": agent["name"], "ip": agent["ip"] }
                setHardware(agent_data, getAgentHardware(agent["id"]), 'wazuh-manager', SOCKET_ADDR)
                setProcess(agent_data, getAgentProcesses(agent["id"], limit=1000),'wazuh-manager', SOCKET_ADDR)
                setOS(agent_data, getAgentOS(agent["id"]), 'wazuh-manager', SOCKET_ADDR)
                setNetIface(agent_data, getAgentNetifaces(agent["id"], limit=1000), 'wazuh-manager', SOCKET_ADDR)
                setNetAddr(agent_data, getAgentNetaddr(agent["id"], limit=1000), 'wazuh-manager', SOCKET_ADDR)
                # TO-DO, validate with os content present
                os_data = getAgentOS(agent["id"])
                if 'Microsoft' in os_data[0]["os"]["name"]: 
                    setHotfix(agent_data, getAgentHotfixes(agent["id"], limit=1000), 'wazuh-manager', SOCKET_ADDR)
                else:
                    logger.debug("Excluding hotfixes, it's not a Microsoft Windows endpoint")
                setProto(agent_data, getAgentProto(agent["id"]), 'wazuh-manager', SOCKET_ADDR)
                setPackage(agent_data, getAgentPackages(agent["id"]), 'wazuh-manager', SOCKET_ADDR)
                setPort(agent_data, getAgentPorts(agent["id"]) , 'wazuh-manager', SOCKET_ADDR)
