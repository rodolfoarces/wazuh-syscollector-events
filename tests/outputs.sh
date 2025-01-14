#!/bin/bash
AGENT_ID=003
USER=wazuh
PASSWORD=wazuh
HOST_IP=127.0.0.1
# https://documentation.wazuh.com/current/user-manual/api/getting-started.html#api-log-in
JWT_TOKEN="$(curl -u $USER:$PASSWORD -k -X POST "https://$HOST_IP:55000/security/user/authenticate?raw=true")"
#JWT_TOKEN="$(curl -u $USER:$PASSWORD -k -X POST "https://$HOST_IP:55000/security/user/authenticate"| jq -r '.data.token')"
#echo JWT_TOKEN=$JWT_TOKEN

# https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Syscollector
curl -k -X GET https://$HOST_IP:55000/syscollector/$AGENT_ID/hardware -H "Authorization: Bearer $JWT_TOKEN" > getAgentHardware.json

curl -k -X GET https://$HOST_IP:55000/syscollector/$AGENT_ID/hotfixes -H "Authorization: Bearer $JWT_TOKEN" > getAgentHotfixes.json

curl -k -X GET https://$HOST_IP:55000/syscollector/$AGENT_ID/netaddr -H "Authorization: Bearer $JWT_TOKEN" > getAgentNetaddr.json

curl -k -X GET https://$HOST_IP:55000/syscollector/$AGENT_ID/netiface -H "Authorization: Bearer $JWT_TOKEN" > getAgentNetiface.json

curl -k -X GET https://$HOST_IP:55000/syscollector/$AGENT_ID/netproto -H "Authorization: Bearer $JWT_TOKEN" > getAgentNetproto.json

curl -k -X GET https://$HOST_IP:55000/syscollector/$AGENT_ID/os -H "Authorization: Bearer $JWT_TOKEN" > getAgentOS.json

curl -k -X GET https://$HOST_IP:55000/syscollector/$AGENT_ID/packages -H "Authorization: Bearer $JWT_TOKEN" > getAgentPackages.json

curl -k -X GET https://$HOST_IP:55000/syscollector/$AGENT_ID/ports -H "Authorization: Bearer $JWT_TOKEN" > getAgentPorts.json

curl -k -X GET https://$HOST_IP:55000/syscollector/$AGENT_ID/processes -H "Authorization: Bearer $JWT_TOKEN" > getAgentProcesses.json
