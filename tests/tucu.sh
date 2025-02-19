#!/bin/bash
# GET TOKEN
TOKEN=$(curl -u wazuh-wui:<pasword> -k -X GET "https://localhost:55000/security/user/authenticate?raw=true")
# Replace wazuh:wazuh with your current credentials)

# Execute the curl on loop (add your agents)
for i in 001 002
do
echo "************************** AGENT_ID: $i *************************************"
#curl -k -X GET "https://localhost:55000/syscollector/$i/hardware" -H "Authorization: Bearer $TOKEN" | jq
#curl -k -X GET "https://localhost:55000/syscollector/$i/processes" -H "Authorization: Bearer $TOKEN" | jq
curl -k -X GET "https://localhost:55000/syscollector/$i/os" -H "Authorization: Bearer $TOKEN" | jq
curl -k -X GET "https://localhost:55000/syscollector/$i/netiface" -H "Authorization: Bearer $TOKEN" | jq
curl -k -X GET "https://localhost:55000/syscollector/$i/netaddr" -H "Authorization: Bearer $TOKEN" | jq
echo "******************************************************************************"
done