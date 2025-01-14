#!/bin/bash
USER=wazuh
PASSWORD=wazuh
HOST_IP=127.0.0.1
JWT_TOKEN="$(curl -u $USER:$PASSWORD -k -X POST "https://$HOST_IP:55000/security/user/authenticate"| jq -r '.data.token')"
echo JWT_TOKEN=$JWT_TOKEN
#curl -k -X GET https://$HOST_IP:55000/ -H "Authorization: Bearer $JWT_TOKEN"